package service

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	msgPath   = "/opinion"
	startPath = "/start"
	endPath   = "/end"
)

type DataFlowDescription struct {
	Start time.Duration
	End   time.Duration
	URL   string
}

type Config struct {
	TimeKoef     float64
	Schedule     []DataFlowDescription
	Name         string
	StartDestURL string
	EndDestURL   string
}

type client struct {
	cfg    Config
	c      http.Client
	ticker time.Ticker
	t0     time.Time
	logger log.Logger
	onStop []func() error
}

func newClient(port int, pairPath, hostNumber, dataflowPath string, timeKoefficient float64, measureTimeOnSingle, testOnLocalhost bool) (*client, error) {
	c := client{
		c: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 15 * time.Second,
		},
		cfg: Config{
			TimeKoef: timeKoefficient,
			Name:     "client-" + hostNumber,
		},
	}

	pairToURL, err := getULRsForPairs(port, pairPath, hostNumber, testOnLocalhost)
	if err != nil {
		return nil, err
	}

	c.cfg.Schedule, err = createSchedule(dataflowPath, timeKoefficient, pairToURL)
	if err != nil {
		return nil, err
	}

	if err := c.setLogger(hostNumber); err != nil {
		return nil, err
	}

	if measureTimeOnSingle && len(c.cfg.Schedule) > 0 {
		addr := c.cfg.Schedule[0].URL[:len(c.cfg.Schedule[0].URL)-len(msgPath)]
		c.cfg.StartDestURL = addr + startPath
		c.cfg.EndDestURL = addr + endPath
	}

	return &c, nil
}

func (r *client) setLogger(hostNumber string) error {
	dst, err := os.OpenFile(path.Join(
		logPath, fmt.Sprintf("client-%v.log", hostNumber)), os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		return err
	}
	r.onStop = append(r.onStop, dst.Close)
	r.logger = *log.New(dst, "", log.Ltime)
	return nil
}

func getULRsForPairs(port int, pairPath, srcHostNumber string, testOnLocalhost bool) (map[string]string, error) {
	pairToURL := make(map[string]string)
	cb := func(record []string) error {
		var dstHostNumber string
		if record[1] == srcHostNumber {
			dstHostNumber = record[2]
		} else if record[2] == srcHostNumber {
			dstHostNumber = record[1]
		} else {
			return nil
		}

		var address string
		if testOnLocalhost {
			address = "http://localhost:" + strconv.Itoa(port)
		} else {
			a, err := getDefaultIP(dstHostNumber)
			if err != nil {
				return err
			}
			address = fmt.Sprintf("http://%v:%v", a.String(), strconv.Itoa(port))
		}

		pairToURL[record[0]] = address + msgPath
		return nil
	}
	return pairToURL, onCSV(pairPath, 3, cb)
}

func createSchedule(dataflowPath string, timeKoefficient float64, pairToURL map[string]string) ([]DataFlowDescription, error) {
	var res []DataFlowDescription
	cb := func(record []string) error {
		url, ok := pairToURL[record[0]]
		if !ok {
			return nil
		}
		start, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			return err
		}
		lifetime, err := strconv.ParseFloat(record[2], 64)
		if err != nil {
			return err
		}
		d := DataFlowDescription{
			Start: time.Duration(start/timeKoefficient) * time.Second,
			End:   time.Duration((start+lifetime)/timeKoefficient) * time.Second,
			URL:   url,
		}
		res = append(res, d)
		return nil
	}
	// TODO: now assuming flows are sorted by start. Sort
	return res, onCSV(dataflowPath, 4, cb)
}

// no worker pool because there will be multiple services which will use multiple cores anyway
func (r *client) run() error {
	r.ticker = *time.NewTicker(time.Duration(float64(time.Second) / r.cfg.TimeKoef))

	r.t0 = time.Now()

	var iteration uint64
	for ; ; iteration += 1 {
		<-r.ticker.C
		if err := r.sendMessages(iteration); err != nil {
			if err == io.EOF {
				r.logger.Println("sent all messages")
				return nil
			}
			log.Println(err)
		}
	}
}

func (r *client) stop() []error {
	var errs []error
	for _, f := range r.onStop {
		if err := f(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func ClearResponse(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func (r *client) sendMessage(description DataFlowDescription, wg *sync.WaitGroup) error {
	req, err := http.NewRequest("PUT", description.URL, bytes.NewReader([]byte("message")))
	if err != nil {
		return err
	}

	r.logger.Printf("sending message to %v\n", description.URL)
	go func() {
		_, _ = r.c.Do(req)
		wg.Done()
	}()
	return nil
}

func (r *client) sendIteration(url string, iteration uint64) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, iteration)

	fmt.Printf("sending %v to %v\n", iteration, url)
	req, err := http.NewRequest("PUT", url, bytes.NewReader(b))
	if err != nil {
		log.Println(err)
		return
	}

	_, _ = r.c.Do(req)
}

func (r *client) sendMessages(iteration uint64) error {
	t := time.Now()
	if len(r.cfg.Schedule) == 0 {
		return io.EOF
	}

	if len(r.cfg.StartDestURL) > 0 {
		go r.sendIteration(r.cfg.StartDestURL, iteration)
	}

	wg := sync.WaitGroup{}
	for i, desc := range r.cfg.Schedule {
		if t.After(r.t0.Add(desc.End)) {
			r.cfg.Schedule = r.cfg.Schedule[i+1:]
			return nil
		}
		if t.Before(r.t0.Add(desc.Start)) {
			continue
		}

		wg.Add(1)
		if err := r.sendMessage(desc, &wg); err != nil {
			return err
		}
	}
	go func() {
		wg.Wait()

		end := time.Now()

		if len(r.cfg.StartDestURL) > 0 {
			go r.sendIteration(r.cfg.EndDestURL, iteration)
		}

		if err := LogTiming(RandomID, r.cfg.Name, iteration, t.UnixNano(), end.UnixNano()); err != nil {
			log.Fatal(err)
		}
	}()
	return nil
}

func RunClient(port int, pairPath, hostNumber, dataflowPath string, timeKoefficient float64, measureTimeOnSingle, testOnLocalhost bool) error {
	c, err := newClient(port, pairPath, hostNumber, dataflowPath, timeKoefficient, measureTimeOnSingle, testOnLocalhost)
	if err != nil {
		return err
	}
	destruct := func() {
		if errs := c.stop(); len(errs) != 0 {
			for _, err := range errs {
				log.Println(err)
			}
		}
	}
	defer destruct()
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		destruct()
	}()

	return c.run()
}
