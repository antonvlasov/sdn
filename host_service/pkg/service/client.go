package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"host-service/pkg/logging"

	semaphore "github.com/dangerousHobo/go-semaphore"
)

type Client struct {
	tasks           Tasks
	name            string // for logging
	testName        string // for logging
	fileClient      *http.Client
	videoClient     *http.Client
	serverFirstPort int
	flowBandwidth   int64
	ctx             context.Context
	cancel          context.CancelFunc
	wg              *sync.WaitGroup
	sem             *semaphore.Semaphore
}

func NewClient(sem *semaphore.Semaphore, tasks Tasks, name string, serverFirstPort int, testName string, flowBandwidth int64) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		tasks:           tasks,
		name:            name,
		testName:        testName,
		fileClient:      &http.Client{},
		videoClient:     &http.Client{Timeout: time.Duration(timeout * float64(time.Second))},
		flowBandwidth:   flowBandwidth,
		ctx:             ctx,
		cancel:          cancel,
		wg:              &sync.WaitGroup{},
		serverFirstPort: serverFirstPort,
		sem:             sem,
	}
}

func (r *Client) Run() {
	for _, t := range r.tasks {
		t := t
		waitUntil(r.ctx, t.Start)
		r.wg.Add(1)

		log.Printf("starting %v task\n", t.Kind)

		go r.executeTask(&t)
	}

	log.Println("launched all tasks")

	r.wg.Wait()

	log.Println("finished all tasks")
}

func (r *Client) Stop() {
	r.cancel()
	r.wg.Wait()
}

func (r *Client) executeTask(t *Task) {
	defer r.wg.Done()

	var err error

	switch t.Kind {
	case KindFile, KindWeb, KindVideo:
		err = r.requestContent(t)
	default:
		panic("unknown kind")
	}

	log.Printf("finished %v task\n", t.Kind)

	if err != nil {
		log.Println(err)
	}
}

func (r *Client) requestContent(t *Task) error {
	task := logging.NewTask(r.testName, t.Server, r.name, t.Kind, 0)
	req := VideoRequest{
		Name:   t.Path,
		Length: r.flowBandwidth * 1024 * 1024 / 8,
	}

	var length int64

	if err := logging.InsertTask(&task); err != nil {
		return err
	}

	tick := time.NewTicker(time.Second)

	for {
		<-tick.C

		task.TotalRequests += 1

		b, err := json.Marshal(req)
		if err != nil {
			return err
		}

		for i := 0; i < retries; i++ {
			if i > 0 {
				log.Println("retry ", i)
			}

			resp, err := request(r.videoClient, "GET", fmt.Sprintf("http://%v:%v/%v/%v", t.Server, r.serverFirstPort+PortOffsets[t.Kind], t.Kind, t.Path), bytes.NewReader(b))
			if err != nil {
				log.Println(err)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				log.Println("bad status code")
				discardBody(resp)
				return fmt.Errorf("%v: %s", resp.StatusCode, mustReadAll(resp.Body))
			}

			task.LastResponseTimestamp = logging.GetFormatedTime()

			log.Println("got time")

			length, err = immitateRead(resp.Body)
			if err != nil {
				discardBody(resp)
				log.Println(err)
				continue
			}

			req.ID = resp.Header.Get(headerID)

			discardBody(resp)
			break
		}

		req.Offset += req.Length

		log.Println("read body")

		task.Bytes += int(length)
		task.ReceivedResponses += 1
		if task.FirstResponseTimestamp == "" {
			task.FirstResponseTimestamp = task.LastResponseTimestamp
		}

		log.Println(task)

		if err := logging.UpdateTask(&task); err != nil {
			return err
		}

		if length < req.Length {
			log.Println("broke after received less bytes")
			break
		}
	}

	log.Println("returning")

	return nil
}
