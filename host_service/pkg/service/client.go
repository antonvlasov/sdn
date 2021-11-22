package service

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"
)

type Settings struct {
	PacketSize             int
	MessageIntervalSeconds int
}
type client struct {
	c http.Client

	commandFile string
	settings    Settings

	opinion []byte
	targets []string
}

func (r *client) makeOpinion() {
	rand.Seed(time.Now().Unix())
	r.opinion = make([]byte, r.settings.PacketSize)
	for i := range r.opinion {
		r.opinion[i] = byte(rand.Int31n(256))
	}
}
func (r *client) run() error {
	for {
		changed, err := r.updateCommand()
		if err != nil {
			return err
		}
		if changed {
			r.makeOpinion()
		}

		if err := r.sendMessages(); err != nil {
			log.Println(err)
		}

		time.Sleep(time.Duration(r.settings.MessageIntervalSeconds) * time.Second)
	}
}
func (r *client) updateCommand() (bool, error) {
	b, err := os.ReadFile(r.commandFile)
	if err != nil {
		return false, err
	}

	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return false, err
	}
	return s != r.settings, err
}
func ClearResponse(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
func (r *client) sendMessage(target string) error {
	req, err := http.NewRequest("PUT", "http://"+target+"/opinion", bytes.NewReader(r.opinion))
	if err != nil {
		return err
	}

	resp, err := r.c.Do(req)
	if err != nil {
		return err
	}
	defer ClearResponse(resp)

	if resp.StatusCode != http.StatusOK {
		log.Printf("%s\n", resp.Body)
		return fmt.Errorf("unexpected status code %v", resp.StatusCode)
	}
	return nil
}
func (r *client) sendMessages() error {
	for _, t := range r.targets {
		if err := r.sendMessage(t); err != nil {
			return err
		}
	}
	return nil
}

func newClient(commandFile string, targets []string) (*client, error) {
	c := client{
		c: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 15 * time.Second,
		},
		commandFile: commandFile,
		targets:     targets,
	}
	_, err := c.updateCommand()
	if err != nil {
		return nil, err
	}
	c.makeOpinion()
	return &c, nil
}

func RunClient(commandFile string, targets []string) error {
	c, err := newClient(commandFile, targets)
	if err != nil {
		return err
	}

	return c.run()
}
