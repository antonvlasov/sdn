package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func waitUntil(ctx context.Context, until time.Time) {
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()

	select {
	case <-timer.C:
		return
	case <-ctx.Done():
		return
	}
}

func ginError(ctx *gin.Context, code int, err error) {
	ctx.Error(err)
	ctx.AbortWithStatusJSON(code, gin.H{"error": err.Error()})
}

func request(c *http.Client, method, url string, body io.Reader) (resp *http.Response, err error) {
	var req *http.Request

	req, err = http.NewRequest(method, url, body)
	if err != nil {
		return
	}

	return c.Do(req)
}

func discardBody(resp *http.Response) {
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func mustReadAll(r io.Reader) []byte {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}

	return b
}

func immitateRead(r io.Reader) (int64, error) {
	return io.Copy(ioutil.Discard, r)
}

func (r Tasks) Less(i, j int) bool {
	return r[i].TimeOffsetSeconds < r[j].TimeOffsetSeconds
}

func (r Tasks) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r Tasks) Len() int {
	return len(r)
}

// Tasks must be sorted by time
func PrepareScenario(path string, speed float64) ([]Task, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var res Tasks
	if err = json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	zero := time.Now()
	for i := range res {
		res[i].Start = zero.Add(time.Duration(res[i].TimeOffsetSeconds * speed * float64(time.Second)))
	}

	return res, nil
}
