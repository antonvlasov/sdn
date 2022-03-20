package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
)

func main() {
	mBit := 1024 * 1024 / 8
	path := "/home/mininet/project/data/server_data/files/"
	koeffs := []int{5, 10, 25, 50, 100, 250, 500, 1000}

	rand.Seed(time.Now().Unix())

	for _, k := range koeffs {
		content := make([]byte, k*mBit)
		_, err := rand.Read(content)
		if err != nil {
			log.Fatal(err)
		}

		if err := os.WriteFile(fmt.Sprintf("%v%vmBit", path, k), content, 0o755); err != nil {
			log.Fatal(err)
		}
	}
}
