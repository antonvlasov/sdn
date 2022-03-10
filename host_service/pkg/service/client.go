package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	ctx             context.Context
	cancel          context.CancelFunc
	wg              *sync.WaitGroup
	sem             *semaphore.Semaphore
}

func NewClient(sem *semaphore.Semaphore, tasks Tasks, name string, serverFirstPort int, testName string) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		tasks:           tasks,
		name:            name,
		testName:        testName,
		fileClient:      &http.Client{},
		videoClient:     &http.Client{Timeout: time.Duration(videoFrameSeconds * float64(time.Second))},
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
	case KindFile:
		err = r.fileRequest(t)
	case KindVideo:
		err = r.videoRequest(t)
	case KindWeb:
		err = r.fileRequest(t)
	default:
		panic("unknown kind")
	}

	log.Printf("finished %v task\n", t.Kind)

	if err != nil {
		log.Println(err)
	}
}

func (r *Client) fileRequest(t *Task) error {
	task := logging.NewTask(r.testName, t.Server, r.name, t.Kind, 1)

	resp, err := request(r.fileClient, "GET", fmt.Sprintf("http://%v:%v/%v/%v", t.Server, r.serverFirstPort+PortOffsets[t.Kind], t.Kind, t.Path), nil)
	if err != nil {
		return err
	}

	defer discardBody(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%v: %s", resp.StatusCode, mustReadAll(resp.Body))
	}

	task.Bytes = immitateRead(resp.Body)

	end := logging.GetFormatedTime()

	task.FirstResponseTimestamp = end
	task.LastResponseTimestamp = end
	task.ReceivedResponses = 1

	return logging.InsertTask(&task)
}

func (r *Client) videoRequest(t *Task) error {
	task := logging.NewTask(r.testName, t.Server, r.name, t.Kind, 0)
	req := VideoRequest{
		Name:   t.Path,
		Length: videoBytesPerSecond * videoFrameSeconds,
	}

	if err := logging.InsertTask(&task); err != nil {
		return err
	}

	tick := time.NewTicker(time.Duration(videoFrameSeconds / t.Speedup * float64(time.Second)))

	for {
		<-tick.C

		task.TotalRequests += 1

		b, err := json.Marshal(req)
		if err != nil {
			return err
		}

		// log.Printf("request %v\n", req)

		resp, err := request(r.videoClient, "GET", fmt.Sprintf("http://%v:%v/%v/%v", t.Server, r.serverFirstPort+PortOffsets[t.Kind], t.Kind, t.Path), bytes.NewReader(b))

		log.Println("got video response")

		req.Offset += req.Length

		if err != nil {
			log.Println(err)
			continue
		}

		log.Println("no error")

		defer discardBody(resp)

		if resp.StatusCode != http.StatusOK {
			log.Println("bad status code")
			return fmt.Errorf("%v: %s", resp.StatusCode, mustReadAll(resp.Body))
		}

		rt := logging.GetFormatedTime()

		log.Println("got time")

		b, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		log.Println("read body")

		var vr VideoResponse
		if err := json.Unmarshal(b, &vr); err != nil {
			return err
		}

		log.Println("unmarshalled")

		task.Bytes += len(vr.Bytes)
		task.ReceivedResponses += 1
		if task.FirstResponseTimestamp == "" {
			task.FirstResponseTimestamp = rt
		}
		task.LastResponseTimestamp = rt

		req.ID = vr.ID

		log.Println(task)

		if err := logging.UpdateTask(&task); err != nil {
			return err
		}

		if len(vr.Bytes) < int(req.Length) {
			log.Println("broke after received less bytes")
			break
		}
	}

	log.Println("returning")

	return nil
}
