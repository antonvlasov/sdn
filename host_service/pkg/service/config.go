package service

import (
	"encoding/csv"
	"io"
	"net"
	"os"
	"strconv"
)

const (
	logPath = "/home/mininet/project/data/logs/"
)

var (
	baseIP = net.ParseIP("10.0.0.0")
)

func onCSV(path string, cols int, cb func([]string) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = ';'
	reader.FieldsPerRecord = cols
	reader.ReuseRecord = true

	_, err = reader.Read()
	if err != nil {
		return err
	}

	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := cb(record); err != nil {
			return err
		}
	}
}
func getDefaultIP(hostNumber string) (net.IP, error) {
	n, err := strconv.Atoi(hostNumber)
	if err != nil {
		return nil, err
	}
	return net.IPv4(baseIP[12]+byte(n>>24),
		baseIP[13]+byte(n>>16),
		baseIP[14]+byte(n>>8),
		baseIP[15]+byte(n)), nil
}
