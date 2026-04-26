package acme

import "sync/atomic"

// IDGenerator generates unique int64 IDs atomically.
type IDGenerator struct {
	counter atomic.Int64
}

// NewIDGenerator creates an ID generator starting at the given seed value.
// Pass 0 to start from 1.
func NewIDGenerator(seed int64) *IDGenerator {
	g := &IDGenerator{}
	if seed <= 0 {
		seed = 0
	}
	g.counter.Store(seed)
	return g
}

// Next returns the next unique ID.
func (g *IDGenerator) Next() int64 {
	return g.counter.Add(1)
}
