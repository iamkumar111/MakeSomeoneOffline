package traffic

import (
	"testing"
	"time"
)

func TestBucketStoreAggregationAndHistory(t *testing.T) {
	bs := NewBucketStore(60)

	now := time.Now().UTC().Truncate(time.Minute).Add(10 * time.Second)
	devID := "dev-test-123"

	// Record metrics in same minute
	bs.RecordMetric(devID, 1024, 2048, 10, 20, 0, now)
	bs.RecordMetric(devID, 1024, 2048, 10, 20, 0, now.Add(10*time.Second))

	// Record metrics in previous minute
	prevMin := now.Add(-1 * time.Minute)
	bs.RecordMetric(devID, 500, 500, 5, 5, 1, prevMin)

	history := bs.QueryHistory(devID, 5*time.Minute)
	if len(history) != 2 {
		t.Fatalf("expected 2 minute buckets in history, got %d", len(history))
	}

	// Verify current minute aggregated correctly
	var currentBucket *MetricBucket
	for _, b := range history {
		if b.BucketTime.Equal(now.Truncate(time.Minute)) {
			copy := b
			currentBucket = &copy
			break
		}
	}

	if currentBucket == nil {
		t.Fatal("expected to find current minute bucket")
	}

	if currentBucket.RxBytes != 2048 || currentBucket.TxBytes != 4096 {
		t.Errorf("expected 2048 Rx / 4096 Tx in aggregated bucket, got %d / %d", currentBucket.RxBytes, currentBucket.TxBytes)
	}

	if currentBucket.RxPackets != 20 || currentBucket.TxPackets != 40 {
		t.Errorf("expected 20 RxPackets / 40 TxPackets, got %d / %d", currentBucket.RxPackets, currentBucket.TxPackets)
	}
}
