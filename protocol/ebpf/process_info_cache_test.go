//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestProcessInfoCacheLifetimeAndClear(t *testing.T) {
	cache := newProcessInfoCache()
	now := time.Unix(100, 0)
	key := processInfoCacheKey{processID: 42, userID: 1000}
	info := &adapter.ConnectionOwner{ProcessID: 42, UserId: 1000, ProcessPaths: []string{"/bin/client"}, PackageNames: []string{"client"}}
	cache.store(key, info, now)

	loaded, ok := cache.load(key, now.Add(processInfoCacheLifetime/2))
	if !ok || loaded != info {
		t.Fatalf("cache load = (%v, %t), want stored process info", loaded, ok)
	}
	if _, ok = cache.load(key, now.Add(processInfoCacheLifetime)); ok {
		t.Fatal("expired process info remained cached")
	}

	cache.store(key, info, now)
	cache.clear()
	if _, ok = cache.load(key, now); ok {
		t.Fatal("cleared process info remained cached")
	}
}

func TestProcessInfoCacheIsBounded(t *testing.T) {
	cache := newProcessInfoCache()
	now := time.Unix(100, 0)
	info := &adapter.ConnectionOwner{ProcessPaths: []string{"/bin/client"}}
	for processID := uint32(0); processID < processInfoCacheCapacity+32; processID++ {
		cache.store(processInfoCacheKey{processID: processID}, info, now)
	}
	cache.access.Lock()
	size := len(cache.entries)
	cache.access.Unlock()
	if size > processInfoCacheCapacity {
		t.Fatalf("cache size = %d, want <= %d", size, processInfoCacheCapacity)
	}
}
