package daemon

import (
	"sync"
	"time"
)

var wallClockLowerBound = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

type startTime struct {
	access  sync.Mutex
	value   time.Time
	trusted bool
}

func (t *startTime) Mark() {
	now := time.Now()
	t.access.Lock()
	t.value = now
	t.trusted = !now.Before(wallClockLowerBound)
	t.access.Unlock()
}

func (t *startTime) Reset() {
	t.access.Lock()
	t.value = time.Time{}
	t.trusted = false
	t.access.Unlock()
}

func (t *startTime) Get() time.Time {
	t.access.Lock()
	defer t.access.Unlock()
	if t.value.IsZero() || t.trusted {
		return t.value
	}
	now := time.Now()
	if now.Before(wallClockLowerBound) {
		return t.value
	}
	t.value = now.Add(-now.Sub(t.value)).Round(0)
	t.trusted = true
	return t.value
}
