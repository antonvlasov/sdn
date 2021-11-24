package main

import (
	"fmt"
	"host-service/pkg/service"
	"log"
	"os"
	"strconv"
	"strings"
)

func simpleParseArgs() (int, string, []string) {
	if len(os.Args) != 4 {
		fmt.Println("incorrect arg count")
		os.Exit(0)
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	commandFile := os.Args[2]
	targets := strings.Split(os.Args[3], ",")
	return port, commandFile, targets
}

func main() {
	fmt.Println("starting host-service...")
	port, commandFile, targets := simpleParseArgs()
	log.Fatal(service.RunService(port, commandFile, targets))
}
