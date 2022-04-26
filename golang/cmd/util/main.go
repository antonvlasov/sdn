package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"golang/pkg/service"
)

func generageScenario() {
	path := "/home/mininet/project/data/scenario/simplest/"
	name := "h1"
	kinds := []string{service.KindFile, service.KindVideo, service.KindWeb}
	pack := 17
	n := 2
	start := 1.5
	offset := 25.0

	rand.Seed(time.Now().Unix())

	tasks := make([]service.Task, pack*n)
	for i := range tasks {
		tasks[i] = service.Task{
			TimeOffsetSeconds: start + offset*float64(i/pack),
			Kind:              kinds[rand.Intn(len(kinds))],
			Server:            "10.0.0.2",
			Path:              "100mBit",
		}
	}

	b, err := json.Marshal(tasks)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(fmt.Sprintf("%v%v.json", path, name), b, 0o755); err != nil {
		log.Fatal(err)
	}
}

func main() {
	generageScenario()
}
