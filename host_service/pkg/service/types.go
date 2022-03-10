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
	videoBytesPerSecond = 302000
	videoFrameSeconds   = 10.0
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
	Speedup           float64
}

type VideoRequest struct {
	Name   string `json:"name"`
	ID     string `json:"id"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
}

type VideoResponse struct {
	ID    string `json:"id"`
	Bytes []byte `json:"bytes"`
}
