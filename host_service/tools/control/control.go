package main

import (
	"encoding/json"
	"host-service/pkg/service"
	"os"
)

func main() {
	settings := service.Settings{
		PacketSize:             32,
		MessageIntervalSeconds: 5,
	}
	if err := CreateControlFileTemplate("config/control", settings); err != nil {
		panic(err)
	}
}

func CreateControlFileTemplate(path string, s service.Settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return os.WriteFile(path, b, 0755)
}
