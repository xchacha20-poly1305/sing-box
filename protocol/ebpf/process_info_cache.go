//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// eBPF process tracking gives us a stable process identity for a socket. The
// identity is still resolved to user-visible metadata through procfs and the
// platform package manager, though. Cache that relatively expensive lookup
// briefly: a process commonly opens many sockets in a short burst, while the
// short lifetime limits stale data if the kernel reuses a PID.
const (
	processInfoCacheCapacity = 256
	processInfoCacheLifetime = time.Second
)

type processInfoCacheKey struct {
	processID uint32
	userID    uint32
}

type processInfoCacheEntry struct {
	info      *adapter.ConnectionOwner
	expiresAt time.Time
}

type processInfoCache struct {
	access  sync.Mutex
	entries map[processInfoCacheKey]processInfoCacheEntry
}

func newProcessInfoCache() *processInfoCache {
	return &processInfoCache{entries: make(map[processInfoCacheKey]processInfoCacheEntry)}
}

func (c *processInfoCache) load(key processInfoCacheKey, now time.Time) (*adapter.ConnectionOwner, bool) {
	if c == nil {
		return nil, false
	}
	c.access.Lock()
	defer c.access.Unlock()
	entry, loaded := c.entries[key]
	if !loaded {
		return nil, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return entry.info, true
}

func (c *processInfoCache) store(key processInfoCacheKey, info *adapter.ConnectionOwner, now time.Time) {
	if c == nil || info == nil {
		return
	}
	c.access.Lock()
	defer c.access.Unlock()
	for cachedKey, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, cachedKey)
		}
	}
	if _, loaded := c.entries[key]; !loaded && len(c.entries) >= processInfoCacheCapacity {
		// Entries are deliberately short-lived. If the cache is full before an
		// expiry pass can reclaim one, evict an arbitrary entry rather than
		// allowing process churn to grow memory without bound.
		for cachedKey := range c.entries {
			delete(c.entries, cachedKey)
			break
		}
	}
	c.entries[key] = processInfoCacheEntry{info: info, expiresAt: now.Add(processInfoCacheLifetime)}
}

func (c *processInfoCache) clear() {
	if c == nil {
		return
	}
	c.access.Lock()
	clear(c.entries)
	c.access.Unlock()
}
