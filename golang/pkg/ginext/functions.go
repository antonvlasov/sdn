package ginext

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GinError(ctx *gin.Context, code int, err error) {
	ctx.Error(err)
	ctx.AbortWithStatusJSON(code, gin.H{"error": err.Error()})
}

func Request(c *http.Client, method, url string, body io.Reader) (resp *http.Response, err error) {
	var req *http.Request

	req, err = http.NewRequest(method, url, body)
	if err != nil {
		return
	}

	return c.Do(req)
}

func DiscardBody(resp *http.Response) {
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func MustReadAll(r io.Reader) []byte {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}

	return b
}

func ImmitateRead(r io.Reader) (int64, error) {
	return io.Copy(ioutil.Discard, r)
}
