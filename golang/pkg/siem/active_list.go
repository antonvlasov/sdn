package siem

import "time"

type Worker struct {
	inCh   chan Event
	getKey func(event Event) string
	onFull func(key string)
	al     ActiveList
}

func NewWorker(getKey func(event Event) string, onFull func(key string), al ActiveList) *Worker {
	return &Worker{
		inCh:   make(chan Event, 100),
		getKey: getKey,
		onFull: onFull,
		al:     al,
	}
}

func (r *Worker) Work() {
	for {
		event := <-r.inCh
		key := r.getKey(event)
		if r.al.Add(key, event) {
			r.onFull(key)
		}
	}
}

func (r *Worker) Push(event Event) {
	r.inCh <- event
}

type ALConfig struct {
	Window     time.Duration
	MaxAllowed int
	MatchFunc  func(event Event) bool
}

type ActiveList struct {
	*ALConfig
	Buckets map[string]*Bucket
}

func NewActiveList(cfg *ALConfig) *ActiveList {
	return &ActiveList{
		Buckets:  make(map[string]*Bucket),
		ALConfig: cfg,
	}
}

func (r *ActiveList) Add(key string, event Event) bool {
	if !r.MatchFunc(event) {
		return false
	}

	if _, ok := r.Buckets[key]; !ok {
		r.Buckets[key] = &Bucket{*NewCycleQueue(r.MaxAllowed)}
	}

	b := r.Buckets[key]

	// delete expired events
	for b.Len() > 0 {
		e := b.Front()
		d := event.Time.Sub(e.Time)
		if d > r.Window {
			b.PopFront()
		} else {
			break
		}
	}

	if b.Len() == r.MaxAllowed {
		b.Clear()
		b.PushBack(event)
		return true
	}

	b.PushBack(event)

	return false
}

type Bucket struct {
	cycleQueue
}

type cycleQueue struct {
	records []Event
	start   int
	end     int
	len     int
}

func NewCycleQueue(size int) *cycleQueue {
	return &cycleQueue{
		records: make([]Event, size),
		start:   0,
		end:     0,
		len:     0,
	}
}

func (r *cycleQueue) PushBack(record Event) {
	if r.len != 0 && r.end == r.start {
		panic("attempt to push to full cycleQueue")
	}

	r.records[r.end] = record

	r.end += 1
	if r.end == len(r.records) {
		r.end = 0
	}

	r.len += 1
}

func (r *cycleQueue) Front() Event {
	if r.len == 0 {
		panic("cycleQueue is empty")
	}

	return r.records[r.start]
}

func (r *cycleQueue) PopFront() {
	if r.len == 0 {
		panic("cycleQueue is empty")
	}

	r.records[r.start] = Event{}

	r.start += 1
	if r.start == len(r.records) {
		r.start = 0
	}

	r.len -= 1
}

func (r *cycleQueue) Clear() {
	if r.len != 0 && r.start <= r.end {
		for i := r.start; i < r.end; i++ {
			r.records[i] = Event{}
		}
	} else if r.len != 0 {
		for i := r.start; i < len(r.records); i++ {
			r.records[i] = Event{}
		}
		for i := 0; i < r.end; i++ {
			r.records[i] = Event{}
		}
	}

	r.start = r.end
	r.len = 0
}

func (r *cycleQueue) Len() int {
	return r.len
}
