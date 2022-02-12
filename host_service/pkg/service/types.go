package service

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

const (
	KindFile  = "file"
	KindWeb   = "web"
	KindVideo = "video"
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

func (r Tasks) Less(i, j int) bool {
	return r[i].TimeOffsetSeconds < r[j].TimeOffsetSeconds
}

func (r Tasks) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r Tasks) Len() int {
	return len(r)
}

// Tasks must be sorted by time
func PrepareScenario(path string, speed float64) ([]Task, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var res Tasks
	if err = json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	zero := time.Now()
	for i := range res {
		res[i].Start = zero.Add(time.Duration(res[i].TimeOffsetSeconds * speed * float64(time.Second)))
	}

	return res, nil
}
