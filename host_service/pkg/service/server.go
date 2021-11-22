package service

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RunServer(port int) error {
	r := gin.Default()
	r.PUT("/opinion", func(c *gin.Context) {
		b, err := c.GetRawData()
		if err != nil {
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		fmt.Printf("%s\n", b)

		io.Copy(io.Discard, bytes.NewReader(b))
		c.Status(http.StatusOK)
	})
	return r.Run(fmt.Sprint(":", port))
}
