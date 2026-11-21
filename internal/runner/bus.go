// Package runner manages the life of scan runs around model.Engine: start,
// pause, resume, cancel, emergency stop, recovery after a restart, result
// import, and the analysis hook after a run. It also holds the event bus that
// feeds the SSE endpoints.
package runner

import "sync"

// Event types. The first four belong to one run; the rest are global.
const (
	EventProgress = "progress" // model.ScanRun
	EventChunk    = "chunk"    // model.Chunk
	EventHost     = "host"     // HostEvent
	EventDone     = "done"     // model.ScanRun
	EventRun      = "run"      // model.ScanRun (status changed)
	EventChange   = "change"   // model.Change
	EventFinding  = "finding"  // model.Finding
)

// Event is one message of the bus.
type Event struct {
	RunID int64
	Type  string
	Data  any
}

// HostEvent is the payload of a "host" event.
type HostEvent struct {
	IP       string `json:"ip"`
	Up       bool   `json:"up"`
	Services int    `json:"services"`
}

func global(typ string) bool { return typ == EventRun || typ == EventChange || typ == EventFinding }

type subscriber struct {
	runID int64 // 0 = global events
	ch    chan Event
}

// Bus fans events out to subscribers. A slow subscriber loses events instead
// of blocking the scan; every progress event carries the full run state, so a
// lost one is repaired by the next.
type Bus struct {
	mu   sync.RWMutex
	subs map[*subscriber]struct{}
}

// NewBus returns an empty bus.
func NewBus() *Bus { return &Bus{subs: map[*subscriber]struct{}{}} }

// Subscribe returns a channel with the events of one run, or with the global
// events when runID is 0. Call cancel to stop.
func (b *Bus) Subscribe(runID int64) (<-chan Event, func()) {
	s := &subscriber{runID: runID, ch: make(chan Event, 256)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return s.ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, s)
			b.mu.Unlock()
		})
	}
}

// Publish sends an event to every matching subscriber without blocking.
func (b *Bus) Publish(e Event) {
	if b == nil {
		return
	}
	g := global(e.Type)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		if (s.runID == 0 && g) || (s.runID != 0 && !g && s.runID == e.RunID) {
			select {
			case s.ch <- e:
			default: // subscriber is slow: drop
			}
		}
	}
}

// Subscribers returns the number of open subscriptions.
func (b *Bus) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
