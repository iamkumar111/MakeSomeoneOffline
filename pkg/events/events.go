package events

import (
	"sync"
	"sync/atomic"
	"time"
)

type EventType string

const (
	EventDeviceSeen           EventType = "device.seen"
	EventDeviceUpdated        EventType = "device.updated"
	EventDeviceOffline        EventType = "device.offline"
	EventTrafficSample        EventType = "traffic.sample"
	EventAlertCreated         EventType = "alert.created"
	EventAlertUpdated         EventType = "alert.updated"
	EventEnforcementRequested EventType = "enforcement.requested"
	EventEnforcementApplied   EventType = "enforcement.applied"
	EventEnforcementRemoved   EventType = "enforcement.removed"
	EventEnforcementFailed    EventType = "enforcement.failed"
	EventIntegrationOnline    EventType = "integration.online"
	EventIntegrationOffline   EventType = "integration.offline"
)

// Event represents an event broadcast to clients via WebSockets and internal subscribers.
type Event struct {
	Sequence uint64      `json:"sequence"`
	Time     time.Time   `json:"time"`
	Type     EventType   `json:"type"`
	SiteID   string      `json:"site_id,omitempty"`
	Data     interface{} `json:"data"`
}

// EventBus distributes events with sequential ordering to subscribers.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[chan Event]struct{}
	seq         atomic.Uint64
}

// NewEventBus creates an initialized EventBus.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[chan Event]struct{}),
	}
}

// Subscribe returns a channel receiving newly published events. Buffer size is configurable.
func (b *EventBus) Subscribe(bufSize int) chan Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan Event, bufSize)
	b.subscribers[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a channel from the subscriber list.
func (b *EventBus) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.subscribers[ch]; ok {
		delete(b.subscribers, ch)
		close(ch)
	}
}

// Publish increments the sequence number and non-blockingly delivers the event to all subscribers.
func (b *EventBus) Publish(eventType EventType, siteID string, data interface{}) Event {
	evt := Event{
		Sequence: b.seq.Add(1),
		Time:     time.Now().UTC(),
		Type:     eventType,
		SiteID:   siteID,
		Data:     data,
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.subscribers {
		select {
		case ch <- evt:
		default:
			// If a subscriber channel is full, drop or let it catch up via REST refetch
		}
	}

	return evt
}

// CurrentSequence returns the highest sequence number generated so far.
func (b *EventBus) CurrentSequence() uint64 {
	return b.seq.Load()
}
