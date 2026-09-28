package traffic

import (
	"sync"
	"time"
)

// MetricBucket aggregates traffic counters over a fixed time slice (e.g. 1-minute or 1-hour).
type MetricBucket struct {
	BucketTime  time.Time `json:"bucket_time"`
	DeviceID    string    `json:"device_id"`
	RxBytes     uint64    `json:"rx_bytes"`
	TxBytes     uint64    `json:"tx_bytes"`
	RxPackets   uint64    `json:"rx_packets"`
	TxPackets   uint64    `json:"tx_packets"`
	DropPackets uint64    `json:"drop_packets"`
}

// BucketStore maintains continuous in-memory time-series metric buckets and rollups.
type BucketStore struct {
	mu           sync.RWMutex
	minuteBuckets map[string]map[int64]*MetricBucket // deviceID -> unixMinute -> MetricBucket
	hourlyBuckets map[string]map[int64]*MetricBucket // deviceID -> unixHour -> MetricBucket
	maxMinutes    int
}

// NewBucketStore creates a metric bucket repository.
func NewBucketStore(maxMinutes int) *BucketStore {
	if maxMinutes <= 0 {
		maxMinutes = 1440 // 24 hours of 1-minute buckets
	}
	return &BucketStore{
		minuteBuckets: make(map[string]map[int64]*MetricBucket),
		hourlyBuckets: make(map[string]map[int64]*MetricBucket),
		maxMinutes:    maxMinutes,
	}
}

// RecordMetric adds incremental bytes and packets to the current minute bucket.
func (bs *BucketStore) RecordMetric(deviceID string, rxBytes, txBytes, rxPackets, txPackets, dropPackets uint64, ts time.Time) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	minuteKey := ts.Truncate(time.Minute).Unix()
	hourKey := ts.Truncate(time.Hour).Unix()

	// 1. Update 1-minute bucket
	devMins, ok := bs.minuteBuckets[deviceID]
	if !ok {
		devMins = make(map[int64]*MetricBucket)
		bs.minuteBuckets[deviceID] = devMins
	}
	bMin, exists := devMins[minuteKey]
	if !exists {
		bMin = &MetricBucket{
			BucketTime: ts.Truncate(time.Minute),
			DeviceID:   deviceID,
		}
		devMins[minuteKey] = bMin
	}
	bMin.RxBytes += rxBytes
	bMin.TxBytes += txBytes
	bMin.RxPackets += rxPackets
	bMin.TxPackets += txPackets
	bMin.DropPackets += dropPackets

	// 2. Update hourly rollup bucket
	devHours, ok := bs.hourlyBuckets[deviceID]
	if !ok {
		devHours = make(map[int64]*MetricBucket)
		bs.hourlyBuckets[deviceID] = devHours
	}
	bHour, exists := devHours[hourKey]
	if !exists {
		bHour = &MetricBucket{
			BucketTime: ts.Truncate(time.Hour),
			DeviceID:   deviceID,
		}
		devHours[hourKey] = bHour
	}
	bHour.RxBytes += rxBytes
	bHour.TxBytes += txBytes
	bHour.RxPackets += rxPackets
	bHour.TxPackets += txPackets
	bHour.DropPackets += dropPackets
}

// QueryHistory returns chronologically sorted metric buckets for a device over the given window.
func (bs *BucketStore) QueryHistory(deviceID string, window time.Duration) []MetricBucket {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	now := time.Now().UTC()
	since := now.Add(-window)

	devMins, ok := bs.minuteBuckets[deviceID]
	if !ok {
		return []MetricBucket{}
	}

	result := make([]MetricBucket, 0)
	for _, b := range devMins {
		if b.BucketTime.After(since) || b.BucketTime.Equal(since) {
			result = append(result, *b)
		}
	}

	return result
}
