package service

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func RunServer(port int, pairPath, hostNumber, dataflowPath string) error {
	dst, err := os.OpenFile(path.Join(logPath, fmt.Sprintf("server-%v.log", hostNumber)), os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		return err
	}
	defer dst.Close()
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		dst.Close()
	}()

	logger := *log.New(dst, "", 1)
	name := "server-" + hostNumber

	tracker := make(map[uint64][2]int64)

	r := gin.Default()
	gin.SetMode(gin.ReleaseMode)
	r.PUT("/opinion", func(c *gin.Context) {
		fmt.Println("entering /opinion")
		b, err := c.GetRawData()
		if err != nil {
			fmt.Printf("error getting raw data: %v\n", err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		logger.Printf("recieved message from %v: %s\n", c.ClientIP(), b)

		io.Copy(io.Discard, bytes.NewReader(b))
		c.Status(http.StatusOK)
	})

	r.PUT("/start", func(c *gin.Context) {
		startTime := time.Now().UnixNano()

		b, err := c.GetRawData()
		if err != nil {
			fmt.Printf("error getting raw data: %v\n", err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		iteration := binary.BigEndian.Uint64(b)
		if timing, ok := tracker[iteration]; ok {
			if err := LogTiming(RandomID, name, iteration, startTime, timing[1]); err != nil {
				log.Fatal(err)
			}
		} else {
			tracker[iteration] = [2]int64{startTime, 0}
		}
		c.Status(http.StatusOK)
	})

	r.PUT("/end", func(c *gin.Context) {
		endTime := time.Now().UnixNano()

		b, err := c.GetRawData()
		if err != nil {
			fmt.Printf("error getting raw data: %v\n", err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}
		iteration := binary.BigEndian.Uint64(b)
		if timing, ok := tracker[iteration]; ok {
			if err := LogTiming(RandomID, name, iteration, timing[0], endTime); err != nil {
				log.Fatal(err)
			}
		} else {
			tracker[iteration] = [2]int64{0, endTime}
		}
		c.Status(http.StatusOK)
	})

	return r.Run(fmt.Sprint(":", port))
}
