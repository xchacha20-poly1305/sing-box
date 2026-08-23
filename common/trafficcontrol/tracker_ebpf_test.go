//go:build with_ebpf

package trafficcontrol

import (
	"sync/atomic"
	"testing"

	"github.com/gofrs/uuid/v5"
)

func TestKernelTrafficIncludedInTotal(t *testing.T) {
	manager := new(Manager)
	tracker := &connTracker{
		metadata: TrackerMetadata{
			ID:       uuid.Must(uuid.NewV4()),
			Upload:   new(atomic.Int64),
			Download: new(atomic.Int64),
		},
		manager: manager,
	}
	manager.connections.Store(tracker.metadata.ID, tracker)

	tracker.CountKernelTraffic(123, 456)
	upload, download := manager.Total()
	if upload != 123 || download != 456 {
		t.Fatalf("unexpected kernel traffic total: upload=%d download=%d", upload, download)
	}
}
