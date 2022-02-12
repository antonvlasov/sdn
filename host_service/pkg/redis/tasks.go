package redis

import (
	"time"

	"github.com/google/uuid"
)

func NewTask(server, client, description string, total int) Task {
	return Task{
		ID:               uuid.NewString(),
		Server:           server,
		Client:           client,
		Description:      description,
		RequestTimestamp: time.Now().Format(time.StampNano),
		Total:            total,
	}
}

func (r *Task) GetMap() map[string]interface{} {
	return map[string]interface{}{
		FieldServer:                 r.Server,
		FieldClient:                 r.Client,
		FieldDescription:            r.Description,
		FieldReceived:               r.Received,
		FieldTotal:                  r.Total,
		FieldRequestTimestamp:       r.RequestTimestamp,
		FieldFirstResponseTimestamp: r.FirstResponseTimestamp,
		FieldLastResponseTimestamp:  r.LastResponseTimestamp,
	}
}

func SetTask(task *Task) (string, error) {
	return task.ID, rdb.HMSet(task.ID, task.GetMap()).Err()
}

func SetTotal(id string, total int) error {
	return rdb.HSet(id, FieldTotal, total).Err()
}

func IncReceived(id string) error {
	return rdb.HIncrBy(id, FieldTotal, 1).Err()
}
