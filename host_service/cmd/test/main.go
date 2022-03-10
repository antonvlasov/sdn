package main

import (
	"log"
	"os"
)

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	name := ""

	f, err := os.OpenFile("/home/mininet/project/data/logs/diag-"+name, os.O_WRONLY|os.O_CREATE, 0o755)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(f)

	defer f.Close()

	log.Println("i work")
}
