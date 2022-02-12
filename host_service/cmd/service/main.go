package main

import (
	"errors"
	"flag"
	"fmt"
	"host-service/pkg/redis"
	"host-service/pkg/service"
	"log"
	"net"
)

type Settings struct {
	ScenarioPath          string // tasks must be sorted by time.
	Speed                 float64
	ControlPort           int
	ServeStartingOnPort   int
	RequestStartingOnPort int
	ServiceName           string
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
				return ipnet.String(), nil
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
	flag.IntVar(&settings.ControlPort, "control-port", 7000, "control port")
	flag.IntVar(&settings.ServeStartingOnPort, "serve-first-port", 7100, fmt.Sprintf("first port to serve on. total %v consecutive ports will be used", len(service.PortOffsets)))
	flag.IntVar(&settings.RequestStartingOnPort, "request-first-port", 7100, fmt.Sprintf("first port to send requests to. total %v consecutive ports will be used", len(service.PortOffsets)))
	flag.StringVar(&settings.ServiceName, "service-name", addr, "service name for logging")
	flag.Parse()

	return &settings
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	settings := parseArgs()

	// start services

	server := service.NewServer(settings.ServeStartingOnPort)
	server.Start()

	var client *service.Client
	if settings.ScenarioPath != "" {
		tasks, err := service.PrepareScenario(settings.ScenarioPath, settings.Speed)
		if err != nil {
			log.Fatal(err)
		}

		if tasks != nil {
			client := service.NewClient(tasks, settings.ServiceName, settings.RequestStartingOnPort)
			client.Start()
		}
	}

	wg := &redis.WaitGroup{}

	wg.Add(1)
	defer wg.Done()

	// stop on signal

	WaitForStopSignal(settings.ControlPort)
	if client != nil {
		client.Stop()
	}
	server.Stop()
}
