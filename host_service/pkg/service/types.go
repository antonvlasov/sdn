package service

import (
	"time"
)

const (
	KindFile  = "file"
	KindWeb   = "web"
	KindVideo = "video"
)

const (
	headerID = "ID"
)

const (
	speed   = 200 * 1024 * 1024 / 8
	timeout = 5.0
	retries = 5
)

var PortOffsets = map[string]int{
	KindFile:  0,
	KindWeb:   1,
	KindVideo: 2,
}

type Tasks []Task

type Task struct {
	TimeOffsetSeconds float64
	Start             time.Time
	Server            string
	Kind              string
	Path              string
}

type VideoRequest struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}
