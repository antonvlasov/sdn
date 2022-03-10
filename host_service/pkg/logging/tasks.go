package logging

import (
	"time"

	"github.com/google/uuid"
)

func NewTask(testName, server, client, description string, total int) Task {
	return Task{
		ID:               uuid.NewString(),
		TestName:         testName,
		Server:           server,
		Client:           client,
		Description:      description,
		RequestTimestamp: GetFormatedTime(),
		TotalRequests:    total,
	}
}

func GetFormatedTime() string {
	return time.Now().Format(time.StampMicro)
}

func InsertTask(t *Task) error {
	_, err := db.Exec("INSERT INTO "+table+" ("+
		FieldID+","+
		FieldTest+","+
		FieldServer+","+
		FieldClient+","+
		FieldDescription+","+
		FieldReceivedResponses+","+
		FieldTotalRequests+","+
		FieldBytes+","+
		FieldRequestTimestamp+","+
		FieldFirstResponseTimestamp+","+
		FieldLastResponseTimestamp+
		") "+
		"VALUES (?,?,?,?,?,?,?,?,?,?,?)", t.ID, t.TestName, t.Server, t.Client, t.Description, t.ReceivedResponses, t.TotalRequests, t.Bytes, t.RequestTimestamp, t.FirstResponseTimestamp, t.LastResponseTimestamp)

	return err
}

func UpdateTask(t *Task) error {
	_, err := db.Exec("UPDATE "+table+
		" SET "+
		FieldID+"=?,"+
		FieldTest+"=?,"+
		FieldServer+"=?,"+
		FieldClient+"=?,"+
		FieldDescription+"=?,"+
		FieldReceivedResponses+"=?,"+
		FieldTotalRequests+"=?,"+
		FieldBytes+"=?,"+
		FieldRequestTimestamp+"=?,"+
		FieldFirstResponseTimestamp+"=?,"+
		FieldLastResponseTimestamp+"=? "+
		"WHERE "+
		FieldID+"=?",
		t.ID, t.TestName, t.Server, t.Client, t.Description, t.ReceivedResponses, t.TotalRequests, t.Bytes, t.RequestTimestamp, t.FirstResponseTimestamp, t.LastResponseTimestamp, t.ID)

	return err
}
