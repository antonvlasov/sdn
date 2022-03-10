package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func WaitForStopSignal() {
	// os interrupt
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("stopping on os signal")
}
