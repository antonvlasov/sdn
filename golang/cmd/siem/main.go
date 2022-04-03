package main

import (
	"time"

	"golang/pkg/siem"
)

func main() {
	cfg := siem.Config{
		ListenOn:      ":7050",
		PortActionURL: "http://localhost:7051/port",
		PortALConfig: &siem.ALConfig{
			Window:     3 * time.Second,
			MaxAllowed: 1,
			MatchFunc:  siem.PortDidNotTransmitt,
		},
	}

	correlator := siem.NewCorrelator(&cfg)
	correlator.Start()
}
