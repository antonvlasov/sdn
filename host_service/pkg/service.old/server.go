package service

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
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

	stats, err := newStats(pairPath, hostNumber, dataflowPath)
	if err != nil {
		return err
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for {
			<-ticker.C
			b := bytes.Buffer{}
			for k, v := range stats.ExpectedPacketsRecieved {
				b.WriteString(k)
				b.WriteRune('\n')

				b.WriteString("expected: ")
				b.WriteString(strconv.Itoa(v))
				b.WriteRune('\n')

				b.WriteString("actual: ")
				b.WriteString(strconv.Itoa(stats.ActualPacketsRecieved[k]))
				b.WriteString("\n\n")
			}

			if err := os.WriteFile(path.Join(logPath, fmt.Sprintf("serverstats-%v.log", hostNumber)), b.Bytes(), 0755); err != nil {
				panic(err)
			}
		}
	}()

	r := gin.Default()
	r.PUT("/opinion", func(c *gin.Context) {
		fmt.Println("entering /opinion")
		b, err := c.GetRawData()
		if err != nil {
			fmt.Printf("error getting raw data: %v\n", err)
			c.AbortWithError(http.StatusBadRequest, err)
			return
		}

		logger.Printf("recieved message from %v: %s\n", c.ClientIP(), b)
		stats.ActualPacketsRecieved[c.ClientIP()] += 1

		io.Copy(io.Discard, bytes.NewReader(b))
		c.Status(http.StatusOK)
	})
	return r.Run(fmt.Sprint(":", port))
}

func newStats(pairPath, hostNumber, dataflowPath string) (*Stats, error) {
	pairToIP, err := getClientIPsForPairs(pairPath, hostNumber)
	if err != nil {
		return nil, err
	}
	stats := Stats{
		ActualPacketsRecieved: make(map[string]int),
	}
	stats.ExpectedPacketsRecieved, err = getExpectedPacketCount(dataflowPath, pairToIP)
	if err != nil {
		return nil, err
	}
	return &stats, nil
}
func getClientIPsForPairs(pairPath, hostNumber string) (map[string]string, error) {
	pairToIP := make(map[string]string)
	cb := func(record []string) error {
		var dstHostNumber string
		if record[1] == hostNumber {
			dstHostNumber = record[2]
		} else if record[2] == hostNumber {
			dstHostNumber = record[1]
		} else {
			return nil
		}
		addr, err := getDefaultIP(dstHostNumber)
		if err != nil {
			return err
		}
		pairToIP[record[0]] = addr.String()
		return nil
	}
	return pairToIP, onCSV(pairPath, 3, cb)
}
func getExpectedPacketCount(dataflowPath string, pairToIP map[string]string) (map[string]int, error) {
	res := make(map[string]int)
	cb := func(record []string) error {
		ip, ok := pairToIP[record[0]]
		if !ok {
			return nil
		}
		lifetime, err := strconv.Atoi(record[2])
		if err != nil {
			return err
		}
		res[ip] += lifetime
		return nil
	}
	return res, onCSV(dataflowPath, 4, cb)
}

type Stats struct {
	ExpectedPacketsRecieved map[string]int
	ActualPacketsRecieved   map[string]int
}
