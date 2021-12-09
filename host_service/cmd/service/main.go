package main

import (
	"flag"
	"fmt"
	"host-service/pkg/service"
	"log"
	"os"
)

func parseFlags() (int, string, string, string, float64) {
	port := flag.Int("port", 0, "port")
	pairPath := flag.String("pair.csv", "", "path to csv containing pairs")
	hostNumber := flag.String("host-number", "", "number of host in mininet")
	dataflowPath := flag.String("dataflow.csv", "", "path to csv containing dataflows")
	timeKoefficient := flag.Float64("time-koefficient", 1, "time koefficient")
	flag.Parse()
	if !flag.Parsed() {
		fmt.Println("flags not parsed")
		os.Exit(0)
	}
	if *hostNumber == "" {
		fmt.Println("hostNumber not provided or equal to zero")
		os.Exit(0)
	}
	return *port, *pairPath, *hostNumber, *dataflowPath, *timeKoefficient
}

func main() {
	fmt.Println("starting host-service...")
	port, pairPath, hostNumber, dataflowPath, timeKoefficient := parseFlags()
	log.Fatal(service.RunService(port, pairPath, hostNumber, dataflowPath, timeKoefficient))
}
