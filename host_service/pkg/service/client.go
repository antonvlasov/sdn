package service

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"syscall"
	"time"
)

type DataFlowDescription struct {
	Start    time.Duration
	End      time.Duration
	Capacity int
	URL      string
}

type Config struct {
	TimeKoef   float64
	Schedule   []DataFlowDescription
	HostNumber string
}

type client struct {
	cfg      Config
	c        http.Client
	payloads map[int][]byte
	ticker   time.Ticker
	t0       time.Time
	logger   log.Logger
	onStop   []func() error
}

func newClient(port int, pairPath, hostNumber, dataflowPath string, timeKoefficient float64) (*client, error) {
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
			TimeKoef:   timeKoefficient,
			HostNumber: hostNumber,
		},
	}
	pairToURL, err := getULRsForPairs(port, pairPath, hostNumber)
	if err != nil {
		return nil, err
	}
	c.cfg.Schedule, err = createSchedule(dataflowPath, timeKoefficient, pairToURL)
	if err != nil {
		return nil, err
	}
	c.payloads = createPayloads(c.cfg.Schedule)
	if err := c.setLogger(hostNumber); err != nil {
		return nil, err
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

func createPayloads(schedule []DataFlowDescription) map[int][]byte {
	res := make(map[int][]byte)
	for _, desc := range schedule {
		_, ok := res[desc.Capacity]
		if ok {
			continue
		}

		payload := make([]byte, desc.Capacity)
		for i := 0; i < desc.Capacity; i++ {
			payload[i] = byte(rand.Intn(256))
		}
		res[desc.Capacity] = payload
	}
	return res
}

func getULRsForPairs(port int, pairPath, srcHostNumber string) (map[string]string, error) {
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
		addr, err := getDefaultIP(dstHostNumber)
		if err != nil {
			return err
		}
		pairToURL[record[0]] = fmt.Sprintf("http://%v:%v/opinion", addr.String(), strconv.Itoa(port))
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
		capacity, err := strconv.Atoi(record[3])
		if err != nil {
			return err
		}
		d := DataFlowDescription{
			Start:    time.Duration(start/timeKoefficient) * time.Second,
			End:      time.Duration((start+lifetime)/timeKoefficient) * time.Second,
			Capacity: capacity,
			URL:      url,
		}
		res = append(res, d)
		return nil
	}
	// TODO: now assuming flows are sorted by start. Sort
	return res, onCSV(dataflowPath, 4, cb)
}

func (r *client) run() error {
	r.ticker = *time.NewTicker(time.Duration(float64(time.Second) / r.cfg.TimeKoef))

	r.t0 = time.Now()
	for {
		<-r.ticker.C
		if err := r.sendMessages(); err != nil {
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

func (r *client) sendMessage(description DataFlowDescription) error {
	req, err := http.NewRequest("PUT", description.URL, bytes.NewReader(r.payloads[description.Capacity]))
	if err != nil {
		return err
	}

	r.logger.Printf("sending message to %v\n", description.URL)
	go r.c.Do(req)
	// resp, err := r.c.Do(req)
	// if err != nil {
	// 	return err
	// }
	// defer ClearResponse(resp)

	// if resp.StatusCode != http.StatusOK {
	// 	log.Printf("%s\n", resp.Body)
	// 	return fmt.Errorf("unexpected status code %v", resp.StatusCode)
	// }
	return nil
}

func (r *client) sendMessages() error {
	t := time.Now()
	if len(r.cfg.Schedule) == 0 {
		return io.EOF
	}
	for i, desc := range r.cfg.Schedule {
		if t.After(r.t0.Add(desc.End)) {
			r.cfg.Schedule = r.cfg.Schedule[i+1:]
			return nil
		}
		if t.Before(r.t0.Add(desc.Start)) {
			continue
		}

		if err := r.sendMessage(desc); err != nil {
			return err
		}

	}
	return nil
}

func RunClient(port int, pairPath, hostNumber, dataflowPath string, timeKoefficient float64) error {
	c, err := newClient(port, pairPath, hostNumber, dataflowPath, timeKoefficient)
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
