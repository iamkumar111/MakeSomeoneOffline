package events

import (
	"testing"
	"time"
)

func TestEventBusPublishSubscribe(t *testing.T) {
	bus := NewEventBus()
	sub := bus.Subscribe(10)
	defer bus.Unsubscribe(sub)

	evt := bus.Publish(EventDeviceSeen, "site-1", map[string]string{"name": "test-device"})
	if evt.Sequence != 1 {
		t.Fatalf("expected sequence 1, got %d", evt.Sequence)
	}

	select {
	case received := <-sub:
		if received.Sequence != 1 {
			t.Errorf("expected sequence 1, got %d", received.Sequence)
		}
		if received.Type != EventDeviceSeen {
			t.Errorf("expected type %s, got %s", EventDeviceSeen, received.Type)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for event")
	}

	evt2 := bus.Publish(EventAlertCreated, "site-1", "alert data")
	if evt2.Sequence != 2 {
		t.Fatalf("expected sequence 2, got %d", evt2.Sequence)
	}
}
