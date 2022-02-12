package redis

import (
	"sync"
)

type WaitGroup struct {
	sync.WaitGroup
}

func (r *WaitGroup) Add(count int) error {
	res := rdb.IncrBy(KeyWaitGroup, int64(count))
	if err := res.Err(); err != nil {
		return err
	}

	r.WaitGroup.Add(count)

	return nil
}

func (r *WaitGroup) Done() error {
	res := rdb.Decr(KeyWaitGroup)
	if err := res.Err(); err != nil {
		return err
	}

	r.WaitGroup.Done()

	return nil
}

func (r *WaitGroup) Wait() {
	r.WaitGroup.Wait()
}
