package logging

import (
	"github.com/go-redis/redis"
)

const (
	FieldID                     = "ID"
	FieldTest                   = "Test"
	FieldServer                 = "Server"
	FieldClient                 = "Client"
	FieldDescription            = "Description"
	FieldReceivedResponses      = "ReceivedResponses"
	FieldTotalRequests          = "TotalRequests"
	FieldBytes                  = "Bytes"
	FieldRequestTimestamp       = "RequestTimestamp"
	FieldFirstResponseTimestamp = "FirstResponseTimestamp"
	FieldLastResponseTimestamp  = "LastResponseTimestamp"
)

type RedisClient redis.Client

type Task struct {
	ID                     string
	TestName               string
	Server                 string
	Client                 string
	Description            string
	ReceivedResponses      int
	TotalRequests          int
	Bytes                  int
	RequestTimestamp       string
	FirstResponseTimestamp string
	LastResponseTimestamp  string
}
