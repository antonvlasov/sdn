package redis

import (
	"github.com/go-redis/redis"
)

const (
	FieldID                     = "ID"
	FieldServer                 = "Server"
	FieldClient                 = "Client"
	FieldDescription            = "Description"
	FieldReceived               = "Received"
	FieldTotal                  = "Total"
	FieldRequestTimestamp       = "RequestTimestamp"
	FieldFirstResponseTimestamp = "FirstResponseTimestamp"
	FieldLastResponseTimestamp  = "LastResponseTimestamp"

	KeyWaitGroup = "WG"
)

type RedisClient redis.Client

type Task struct {
	ID                     string
	Server                 string
	Client                 string
	Description            string
	Received               int
	Total                  int
	RequestTimestamp       string
	FirstResponseTimestamp string
	LastResponseTimestamp  string
}
