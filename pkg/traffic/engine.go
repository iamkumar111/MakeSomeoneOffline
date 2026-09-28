package traffic

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/open-netcut/open-netcut/pkg/events"
)

// DeviceTrafficStats maintains rolling byte counters and rates for an endpoint.
type DeviceTrafficStats struct {
	DeviceID    string    `json:"device_id"`
	PrimaryIP   string    `json:"primary_ip"`
	PrimaryMAC  string    `json:"primary_mac"`
	RxBytes     uint64    `json:"rx_bytes"`
	TxBytes     uint64    `json:"tx_bytes"`
	RxPackets   uint64    `json:"rx_packets"`
	TxPackets   uint64    `json:"tx_packets"`
	RxRateBps   float64   `json:"rx_rate_bps"`
	TxRateBps   float64   `json:"tx_rate_bps"`
	LastUpdated time.Time `json:"last_updated"`

	// Internal state for moving average rate calculation
	lastRxBytes uint64
	lastTxBytes uint64
	lastSample  time.Time
}

// FlowRecord captures a summarized flow sample.
type FlowRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"src_ip"`
	DestIP      string    `json:"dst_ip"`
	SourcePort  int       `json:"src_port"`
	DestPort    int       `json:"dst_port"`
	Protocol    string    `json:"protocol"` // "tcp", "udp", "icmp"
	Bytes       uint64    `json:"bytes"`
	Packets     uint64    `json:"packets"`
}

// TelemetryEngine tracks per-device bandwidth and generates aggregated traffic events.
type TelemetryEngine struct {
	mu            sync.RWMutex
	deviceStats   map[string]*DeviceTrafficStats // keyed by DeviceID
	ipToDeviceID  map[string]string
	ifaceTotals   InterfaceTotals
	trafficSource string
	eventBus      *events.EventBus
	siteID        string
	stopCh        chan struct{}
}

// InterfaceTotals holds gateway-wide counters from /proc/net/dev.
type InterfaceTotals struct {
	RxBytes     uint64    `json:"rx_bytes"`
	TxBytes     uint64    `json:"tx_bytes"`
	RxRateBps   float64   `json:"rx_rate_bps"`
	TxRateBps   float64   `json:"tx_rate_bps"`
	LastUpdated time.Time `json:"last_updated"`
	lastRx      uint64
	lastTx      uint64
	lastSample  time.Time
}

// NewTelemetryEngine creates an initialized TelemetryEngine.
func NewTelemetryEngine(siteID string, eventBus *events.EventBus) *TelemetryEngine {
	if siteID == "" {
		siteID = "default"
	}
	te := &TelemetryEngine{
		deviceStats:  make(map[string]*DeviceTrafficStats),
		ipToDeviceID: make(map[string]string),
		eventBus:     eventBus,
		siteID:       siteID,
		stopCh:       make(chan struct{}),
	}

	return te
}

// RegisterDeviceBinding maps an IP to a DeviceID for flow attribution.
func (te *TelemetryEngine) RegisterDeviceBinding(deviceID, ip, mac string) {
	te.mu.Lock()
	defer te.mu.Unlock()

	te.ipToDeviceID[ip] = deviceID
	if _, exists := te.deviceStats[deviceID]; !exists {
		te.deviceStats[deviceID] = &DeviceTrafficStats{
			DeviceID:    deviceID,
			PrimaryIP:   ip,
			PrimaryMAC:  mac,
			LastUpdated: time.Now().UTC(),
			lastSample:  time.Now().UTC(),
		}
	}
}

// RecordFlow ingests a flow observation and updates both source and destination counters.
func (te *TelemetryEngine) RecordFlow(flow FlowRecord) {
	te.mu.Lock()
	defer te.mu.Unlock()

	now := flow.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Update Tx for source device if known
	if srcDevID, ok := te.ipToDeviceID[flow.SourceIP]; ok {
		stats := te.getOrCreateStatsLocked(srcDevID, flow.SourceIP)
		stats.TxBytes += flow.Bytes
		stats.TxPackets += flow.Packets
		stats.LastUpdated = now
	}

	// Update Rx for destination device if known
	if dstDevID, ok := te.ipToDeviceID[flow.DestIP]; ok {
		stats := te.getOrCreateStatsLocked(dstDevID, flow.DestIP)
		stats.RxBytes += flow.Bytes
		stats.RxPackets += flow.Packets
		stats.LastUpdated = now
	}
}

// RecordDevicePacket directly records bytes and packets for a known device.
func (te *TelemetryEngine) RecordDevicePacket(deviceID string, rxBytes, txBytes, rxPackets, txPackets uint64) {
	te.mu.Lock()
	defer te.mu.Unlock()

	stats := te.getOrCreateStatsLocked(deviceID, "")
	stats.RxBytes += rxBytes
	stats.TxBytes += txBytes
	stats.RxPackets += rxPackets
	stats.TxPackets += txPackets
	stats.LastUpdated = time.Now().UTC()
}

func (te *TelemetryEngine) getOrCreateStatsLocked(deviceID, ip string) *DeviceTrafficStats {
	stats, ok := te.deviceStats[deviceID]
	if !ok {
		stats = &DeviceTrafficStats{
			DeviceID:    deviceID,
			PrimaryIP:   ip,
			LastUpdated: time.Now().UTC(),
			lastSample:  time.Now().UTC(),
		}
		te.deviceStats[deviceID] = stats
	}
	return stats
}

// CalculateRates computes instantaneous bytes-per-second rates and publishes traffic samples.
func (te *TelemetryEngine) CalculateRates() {
	te.mu.Lock()
	defer te.mu.Unlock()

	now := time.Now().UTC()
	sampleList := make([]DeviceTrafficStats, 0, len(te.deviceStats))

	for _, s := range te.deviceStats {
		interval := now.Sub(s.lastSample).Seconds()
		if interval >= 0.5 {
			rxDelta := s.RxBytes - s.lastRxBytes
			txDelta := s.TxBytes - s.lastTxBytes

			s.RxRateBps = float64(rxDelta*8) / interval
			s.TxRateBps = float64(txDelta*8) / interval

			s.lastRxBytes = s.RxBytes
			s.lastTxBytes = s.TxBytes
			s.lastSample = now
		}
		sampleList = append(sampleList, *s)
	}

	if te.eventBus != nil && len(sampleList) > 0 {
		te.eventBus.Publish(events.EventTrafficSample, te.siteID, sampleList)
	}
}

// StartRateCalculator periodically updates rates and broadcasts traffic events.
func (te *TelemetryEngine) StartRateCalculator(ctx context.Context, interval time.Duration) {
	if interval < 1*time.Second {
		interval = 2 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-te.stopCh:
				return
			case <-ticker.C:
				te.CalculateRates()
			}
		}
	}()
}

// Stop terminates background calculations.
func (te *TelemetryEngine) Stop() {
	close(te.stopCh)
}

// TopTalkers returns the top N devices sorted by live rate first, then total bytes.
// Sorting by rate (not just cumulative bytes) keeps the list live instead of
// frozen on historic totals.
func (te *TelemetryEngine) TopTalkers(limit int) []DeviceTrafficStats {
	te.mu.RLock()
	defer te.mu.RUnlock()

	list := make([]DeviceTrafficStats, 0, len(te.deviceStats))
	for _, s := range te.deviceStats {
		list = append(list, *s)
	}

	sort.Slice(list, func(i, j int) bool {
		ri := list[i].RxRateBps + list[i].TxRateBps
		rj := list[j].RxRateBps + list[j].TxRateBps
		if ri != rj {
			return ri > rj
		}
		totalI := list[i].RxBytes + list[i].TxBytes
		totalJ := list[j].RxBytes + list[j].TxBytes
		if totalI != totalJ {
			return totalI > totalJ
		}
		return list[i].PrimaryIP < list[j].PrimaryIP
	})

	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list
}

// GetDeviceStats returns the current traffic stats for a specific device.
func (te *TelemetryEngine) GetDeviceStats(deviceID string) (*DeviceTrafficStats, bool) {
	te.mu.RLock()
	defer te.mu.RUnlock()

	stats, ok := te.deviceStats[deviceID]
	if !ok {
		return nil, false
	}
	copy := *stats
	return &copy, true
}

// SetInterfaceTotals stores gateway-wide counters (from /proc/net/dev).
func (te *TelemetryEngine) SetInterfaceTotals(tot InterfaceTotals) {
	te.mu.Lock()
	defer te.mu.Unlock()
	te.ifaceTotals = tot
}

// GetInterfaceTotals returns the last gateway-wide counters.
func (te *TelemetryEngine) GetInterfaceTotals() InterfaceTotals {
	te.mu.RLock()
	defer te.mu.RUnlock()
	return te.ifaceTotals
}

// SetTrafficSource records which per-IP source feeds TopTalkers.
func (te *TelemetryEngine) SetTrafficSource(src string) {
	te.mu.Lock()
	defer te.mu.Unlock()
	te.trafficSource = src
}

// GetTrafficSource returns the active per-IP source.
func (te *TelemetryEngine) GetTrafficSource() string {
	te.mu.RLock()
	defer te.mu.RUnlock()
	if te.trafficSource == "" {
		return "unavailable"
	}
	return te.trafficSource
}
