package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
)

func WaitForStopSignal(controlPort int) {
	// os interrupt
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// control signal
	controlChan := make(chan struct{})
	r := gin.Default()

	r.POST("/stop", func(c *gin.Context) {
		controlChan <- struct{}{}
	})

	go func() {
		if err := r.Run(fmt.Sprintf(":%v", controlPort)); err != nil {
			log.Fatal(err)
		}
	}()

	select {
	case <-sigChan:
		log.Println("stopping on os signal")
	case <-controlChan:
		log.Println("stopping on control signal")
	}
}
