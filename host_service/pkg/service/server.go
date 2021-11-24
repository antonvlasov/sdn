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
		fmt.Println("entering /opinion")
		b, err := c.GetRawData()
		if err != nil {
			fmt.Printf("error getting raw data: %v\n", err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		fmt.Printf("got data: %s\n", b)

		io.Copy(io.Discard, bytes.NewReader(b))
		c.Status(http.StatusOK)
	})
	return r.Run(fmt.Sprint(":", port))
}
