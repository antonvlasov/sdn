package service

import (
	"context"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptrace"
	"time"

	"github.com/gin-gonic/gin"
)

var dump = make([]byte, 1024)

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

func (r *Client) request(method, url string, body io.Reader) (resp *http.Response, fb time.Time, err error) {
	var req *http.Request

	req, err = http.NewRequest(method, url, body)
	if err != nil {
		return
	}

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			fb = time.Now()
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err = r.c.Do(req)

	return
}

func discardBody(resp *http.Response) {
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func mustReadAll(r io.ReadCloser) []byte {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}

	return b
}

func immitateRead(r io.ReadCloser) int {
	total := 0

	for n, err := r.Read(dump); n != 0 || err != io.EOF; n, err = r.Read(dump) {
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		total += n
	}

	return total
}
