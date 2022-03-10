package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"host-service/pkg/service"

	semaphore "github.com/dangerousHobo/go-semaphore"
)

type Settings struct {
	ScenarioPath          string // tasks must be sorted by time.
	Speed                 float64
	ServeStartingOnPort   int
	RequestStartingOnPort int
	ServiceName           string
	SemaphoreName         string
	TestName              string
}

func getMyIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	if len(addrs) > 2 {
		return "", errors.New("too many ip addresses: can't choose")
	}

	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", errors.New("no valid ip addresses")
}

func parseArgs() *Settings {
	var settings Settings

	addr, err := getMyIP()
	if err != nil {
		log.Fatal(err)
	}

	flag.StringVar(&settings.ScenarioPath, "scenario", "", "path to scenario file")
	flag.Float64Var(&settings.Speed, "speed", 1, "speed")
	flag.IntVar(&settings.ServeStartingOnPort, "serve-first-port", 7100, fmt.Sprintf("first port to serve on. total %v consecutive ports will be used", len(service.PortOffsets)))
	flag.IntVar(&settings.RequestStartingOnPort, "request-first-port", 7100, fmt.Sprintf("first port to send requests to. total %v consecutive ports will be used", len(service.PortOffsets)))
	flag.StringVar(&settings.ServiceName, "service-name", addr, "service name for logging")
	flag.StringVar(&settings.SemaphoreName, "sem-name",
		"", "semaphore name for sync")
	flag.StringVar(&settings.TestName, "test-name", "", "global test name for logging")
	flag.Parse()

	if settings.SemaphoreName == "" {
		log.Fatal("semaphore name must not be empty")
	}

	return &settings
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	settings := parseArgs()

	f, err := os.OpenFile("/home/mininet/project/data/logs/diag-"+settings.ServiceName, os.O_WRONLY|os.O_CREATE, 0o755)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(f)

	defer f.Close()

	log.Printf("test name is %v\n", settings.TestName)

	var sem semaphore.Semaphore
	// default for testing two nodes without mininet
	if err := sem.Open(settings.SemaphoreName, 0o777, 2); err != nil {
		log.Fatal(err)
	}

	log.Printf("opened semaphore %v\n", settings.SemaphoreName)

	// start services

	server := service.NewServer(settings.ServeStartingOnPort)
	server.Start()

	log.Println("started server")

	var client *service.Client
	if settings.ScenarioPath != "" {
		tasks, err := service.PrepareScenario(settings.ScenarioPath, settings.Speed)
		if err != nil {
			log.Fatal(err)
		}

		if tasks != nil {
			client := service.NewClient(&sem, tasks, settings.ServiceName, settings.RequestStartingOnPort, settings.TestName)
			// block
			client.Run()

			fmt.Println("client done")
		}
	}

	// decrement and close semaphore

	if err := sem.Wait(); err != nil {
		log.Fatal(err)
	}

	if err := sem.Close(); err != nil {
		log.Fatal(err)
	}

	log.Println("decremented and closed semaphore")

	// stop on signal

	WaitForStopSignal()
	if client != nil {
		client.Stop()
	}
	server.Stop()
}
