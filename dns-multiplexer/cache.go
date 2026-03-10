package main

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheKey struct {
	Name  string
	Type  uint16
	Class uint16
}

type cacheEntry struct {
	response  []byte
	expiresAt time.Time
	element   *list.Element
}

// DNSCache is an LRU cache for DNS responses with TTL-based expiry.
type DNSCache struct {
	mu      sync.Mutex
	maxSize int
	items   map[cacheKey]*cacheEntry
	order   *list.List
}

func NewDNSCache(maxSize int) *DNSCache {
	return &DNSCache{
		maxSize: maxSize,
		items:   make(map[cacheKey]*cacheEntry),
		order:   list.New(),
	}
}

func extractKey(raw []byte) (cacheKey, bool) {
	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil || len(msg.Question) == 0 {
		return cacheKey{}, false
	}
	q := msg.Question[0]
	return cacheKey{
		Name:  strings.ToLower(q.Name),
		Type:  q.Qtype,
		Class: q.Qclass,
	}, true
}

func minTTL(raw []byte) time.Duration {
	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		return 0
	}

	var min uint32
	first := true
	for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range rrs {
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			ttl := rr.Header().Ttl
			if first || ttl < min {
				min = ttl
				first = false
			}
		}
	}
	if first {
		return 0 // no RRs
	}
	return time.Duration(min) * time.Second
}

// Get retrieves a cached response. On hit, rewrites the transaction ID to match the query.
func (c *DNSCache) Get(query []byte) ([]byte, bool) {
	key, ok := extractKey(query)
	if !ok {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.items[key]
	if !exists {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		c.order.Remove(entry.element)
		delete(c.items, key)
		return nil, false
	}

	c.order.MoveToFront(entry.element)
	resp := make([]byte, len(entry.response))
	copy(resp, entry.response)

	// Rewrite transaction ID (first 2 bytes) to match the query
	if len(query) >= 2 && len(resp) >= 2 {
		resp[0] = query[0]
		resp[1] = query[1]
	}
	return resp, true
}

// Put stores a DNS response in the cache.
func (c *DNSCache) Put(query []byte, response []byte) {
	key, ok := extractKey(query)
	if !ok {
		return
	}
	ttl := minTTL(response)
	if ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.items[key]; exists {
		c.order.Remove(entry.element)
		delete(c.items, key)
	}

	// Evict LRU if at capacity
	for c.order.Len() >= c.maxSize {
		back := c.order.Back()
		if back == nil {
			break
		}
		evictKey := back.Value.(cacheKey)
		c.order.Remove(back)
		delete(c.items, evictKey)
	}

	stored := make([]byte, len(response))
	copy(stored, response)
	elem := c.order.PushFront(key)
	c.items[key] = &cacheEntry{
		response:  stored,
		expiresAt: time.Now().Add(ttl),
		element:   elem,
	}
}
