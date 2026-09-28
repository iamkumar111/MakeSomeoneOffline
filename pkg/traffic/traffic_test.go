package traffic

import (
	"testing"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
)

func TestTelemetryEngineFlowAndTopTalkers(t *testing.T) {
	bus := events.NewEventBus()
	engine := NewTelemetryEngine("test-site", bus)
	defer engine.Stop()

	// Register bindings
	engine.RegisterDeviceBinding("dev-1", "192.168.1.100", "00:11:22:33:44:55")
	engine.RegisterDeviceBinding("dev-2", "192.168.1.101", "aa:bb:cc:dd:ee:ff")

	// Ingest flows
	engine.RecordFlow(FlowRecord{
		Timestamp: time.Now(),
		SourceIP:  "192.168.1.100",
		DestIP:    "192.168.1.101",
		Protocol:  "tcp",
		Bytes:     50000,
		Packets:   35,
	})

	engine.RecordFlow(FlowRecord{
		Timestamp: time.Now(),
		SourceIP:  "192.168.1.100",
		DestIP:    "8.8.8.8",
		Protocol:  "udp",
		Bytes:     150000,
		Packets:   100,
	})

	// Check dev-1 stats
	stats1, ok := engine.GetDeviceStats("dev-1")
	if !ok {
		t.Fatal("expected stats for dev-1")
	}
	if stats1.TxBytes != 200000 {
		t.Errorf("expected 200000 TxBytes, got %d", stats1.TxBytes)
	}

	// Check dev-2 stats
	stats2, ok := engine.GetDeviceStats("dev-2")
	if !ok {
		t.Fatal("expected stats for dev-2")
	}
	if stats2.RxBytes != 50000 {
		t.Errorf("expected 50000 RxBytes, got %d", stats2.RxBytes)
	}

	// Top Talkers check
	top := engine.TopTalkers(5)
	if len(top) < 2 {
		t.Fatalf("expected at least 2 top talkers, got %d", len(top))
	}
	if top[0].DeviceID != "dev-1" {
		t.Errorf("expected dev-1 as #1 top talker, got %s", top[0].DeviceID)
	}

	// Rate calculation check
	engine.CalculateRates()
}
