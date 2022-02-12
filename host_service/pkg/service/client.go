package service

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type Client struct {
	tasks           Tasks
	name            string // for logging
	c               *http.Client
	serverFirstPort int
	ctx             context.Context
	cancel          context.CancelFunc
	wg              *sync.WaitGroup
}

func NewClient(tasks Tasks, name string, serverFirstPort int) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		tasks:           tasks,
		name:            name,
		c:               &http.Client{},
		ctx:             ctx,
		cancel:          cancel,
		wg:              &sync.WaitGroup{},
		serverFirstPort: serverFirstPort,
	}
}

func (r *Client) Start() {
	for _, t := range r.tasks {
		waitUntil(r.ctx, t.Start)
		go r.executeTask(&t)
	}
}

func (r *Client) Stop() {
	r.cancel()
	r.wg.Wait()
}

func (r *Client) executeTask(t *Task) {
	r.wg.Add(1)
	defer r.wg.Done()

	var err error

	switch t.Kind {
	case KindFile:
		err = r.fileRequest(t)
	case KindVideo:
	case KindWeb:
	default:
		panic("unknown kind")
	}

	if err != nil {
		log.Println(err)
	}
}

func (r *Client) fileRequest(t *Task) error {
	start := time.Now()

	resp, fb, err := r.request("GET", fmt.Sprintf("http://%v:%v/file/%v", t.Server, r.serverFirstPort+PortOffsets[KindFile], t.Path), nil)
	end := time.Now()

	if err != nil {
		return err
	}

	defer discardBody(resp)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%v: %s", resp.StatusCode, mustReadAll(resp.Body))
	}

	fmt.Printf("ttfb: %v ns; transfer: %v ns\n", fb.Sub(start).Nanoseconds(), end.Sub(fb).Nanoseconds())

	return nil
}
