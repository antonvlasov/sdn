package main

import (
	"flag"
	"fmt"
	"host-service/pkg/service"
	"log"
	"os"

	"github.com/google/uuid"
)

func parseFlags() (int, string, string, string, float64, bool, bool) {
	port := flag.Int("port", 0, "port")
	pairPath := flag.String("pair.csv", "", "path to csv containing pairs")
	hostNumber := flag.String("host-number", "", "number of host in mininet")
	dataflowPath := flag.String("dataflow.csv", "", "path to csv containing dataflows")
	timeKoefficient := flag.Float64("time-koefficient", 1, "time koefficient")
	measureTimeOnSingle := flag.Bool("measure-single", false, "measure time assuming messages are only sent to one host")
	testOnLocalhost := flag.Bool("localhost", false, "send all to localhost")
	flag.Parse()
	if !flag.Parsed() {
		fmt.Println("flags not parsed")
		os.Exit(0)
	}
	if *hostNumber == "" {
		fmt.Println("hostNumber not provided or equal to zero")
		os.Exit(0)
	}
	return *port, *pairPath, *hostNumber, *dataflowPath, *timeKoefficient, *measureTimeOnSingle, *testOnLocalhost
}

func main() {
	fmt.Println("starting host-service...")
	port, pairPath, hostNumber, dataflowPath, timeKoefficient, measureTimeOnSingle, testOnLocalhost := parseFlags()
	randomID := uuid.NewString()
	log.Fatal(service.RunService(port, pairPath, hostNumber, dataflowPath, timeKoefficient, measureTimeOnSingle, randomID, testOnLocalhost))
}
