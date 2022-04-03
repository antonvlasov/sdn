package siem

import "time"

const (
	NEW         = 0
	IN_PROGRESS = 1
	TRANSMITTED = 2
	DEAD        = 3
)

type Event struct {
	Time      time.Time
	PortState *PortState
	FlowState *FlowState
}

type PortState struct {
	Mac   string `json:"mac"`
	State int    `json:"state"`
}

type FlowState struct{}

func GetPortStateKey(event Event) string {
	return event.PortState.Mac
}

func PortDidNotTransmitt(event Event) bool {
	return event.PortState.State == IN_PROGRESS
}
