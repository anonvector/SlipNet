package main

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Resolver represents an upstream DNS resolver.
type Resolver struct {
	Addr string // "IP:port" for UDP mode
	URL  string // full HTTPS URL for DoH mode
}

func (r Resolver) String() string {
	if r.URL != "" {
		return r.URL
	}
	return r.Addr
}

type resolverStats struct {
	sent uint64
	ok   uint64
	fail uint64
}

// ResolverPool manages a set of upstream resolvers with health tracking.
type ResolverPool struct {
	resolvers    []Resolver
	mode         string // "round-robin" or "random"
	doh          bool
	mu           sync.RWMutex
	healthy      map[Resolver]bool
	healthyCache []Resolver
	stats        map[Resolver]*resolverStats
	failStreak   map[Resolver]int
	rrIndex      uint64
}

func NewResolverPool(resolvers []Resolver, mode string, doh bool) *ResolverPool {
	p := &ResolverPool{
		resolvers:    resolvers,
		mode:         mode,
		doh:          doh,
		healthy:      make(map[Resolver]bool, len(resolvers)),
		healthyCache: make([]Resolver, len(resolvers)),
		stats:        make(map[Resolver]*resolverStats, len(resolvers)),
		failStreak:   make(map[Resolver]int, len(resolvers)),
	}
	copy(p.healthyCache, resolvers)
	for _, r := range resolvers {
		p.healthy[r] = true
		p.stats[r] = &resolverStats{}
	}
	return p
}

func (p *ResolverPool) rebuildHealthyCache() {
	cache := make([]Resolver, 0, len(p.resolvers))
	for _, r := range p.resolvers {
		if p.healthy[r] {
			cache = append(cache, r)
		}
	}
	if len(cache) == 0 {
		cache = make([]Resolver, len(p.resolvers))
		copy(cache, p.resolvers)
	}
	p.healthyCache = cache
}

func (p *ResolverPool) GetNext() Resolver {
	p.mu.RLock()
	healthy := p.healthyCache
	p.mu.RUnlock()

	if p.mode == "random" {
		return healthy[rand.Intn(len(healthy))]
	}
	idx := atomic.AddUint64(&p.rrIndex, 1) - 1
	return healthy[idx%uint64(len(healthy))]
}

// SendQuery sends a DNS query to a resolver using the appropriate transport.
func (p *ResolverPool) SendQuery(data []byte, r Resolver) ([]byte, error) {
	if p.doh {
		return sendQueryDoH(data, r.URL, upstreamTimeout)
	}
	return sendQueryUDP(data, r.Addr, upstreamTimeout)
}

func (p *ResolverPool) MarkSent(r Resolver) {
	p.mu.RLock()
	s := p.stats[r]
	p.mu.RUnlock()
	atomic.AddUint64(&s.sent, 1)
}

func (p *ResolverPool) MarkSuccess(r Resolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats[r]
	atomic.AddUint64(&s.ok, 1)
	p.failStreak[r] = 0
	if !p.healthy[r] {
		p.healthy[r] = true
		p.rebuildHealthyCache()
	}
}

func (p *ResolverPool) MarkFailure(r Resolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats[r]
	atomic.AddUint64(&s.fail, 1)
	p.failStreak[r]++
	if p.failStreak[r] >= 3 && p.healthy[r] {
		p.healthy[r] = false
		p.rebuildHealthyCache()
	}
}

func (p *ResolverPool) HealthCheck() {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
	msg.RecursionDesired = true
	query, err := msg.Pack()
	if err != nil {
		return
	}

	type result struct {
		r     Resolver
		alive bool
	}

	ch := make(chan result, len(p.resolvers))
	for _, r := range p.resolvers {
		go func(r Resolver) {
			_, err := p.SendQuery(query, r)
			ch <- result{r, err == nil}
		}(r)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for range p.resolvers {
		res := <-ch
		p.healthy[res.r] = res.alive
		if res.alive {
			p.failStreak[res.r] = 0
		}
	}
	p.rebuildHealthyCache()
}

func (p *ResolverPool) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.healthyCache)
}

func (p *ResolverPool) StatsString() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var result string
	for _, r := range p.resolvers {
		s := p.stats[r]
		status := "UP"
		if !p.healthy[r] {
			status = "DOWN"
		}
		result += fmt.Sprintf("  %40s [%4s] sent=%-6d ok=%-6d fail=%d\n",
			r.String(), status,
			atomic.LoadUint64(&s.sent),
			atomic.LoadUint64(&s.ok),
			atomic.LoadUint64(&s.fail))
	}
	return result
}

// ProbeResolvers tests all resolvers and returns only working ones.
func ProbeResolvers(pool *ResolverPool) []Resolver {
	slog.Info("Probing resolvers...", "count", len(pool.resolvers))

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
	msg.RecursionDesired = true
	query, _ := msg.Pack()

	type result struct {
		r     Resolver
		alive bool
	}

	ch := make(chan result, len(pool.resolvers))
	workers := len(pool.resolvers)
	if workers > 30 {
		workers = 30
	}
	sem := make(chan struct{}, workers)

	for _, r := range pool.resolvers {
		sem <- struct{}{}
		go func(r Resolver) {
			defer func() { <-sem }()
			_, err := pool.SendQuery(query, r)
			ch <- result{r, err == nil}
		}(r)
	}

	var working []Resolver
	for range pool.resolvers {
		res := <-ch
		if res.alive {
			slog.Info(fmt.Sprintf("  \033[32mUP\033[0m   %s", res.r))
			working = append(working, res.r)
		} else {
			slog.Info(fmt.Sprintf("  \033[31mDOWN\033[0m %s", res.r))
		}
	}

	if len(working) == 0 {
		slog.Warn("No working resolvers found! Keeping all.")
		return pool.resolvers
	}

	slog.Info("Probe complete", "working", len(working), "total", len(pool.resolvers))
	return working
}

// PoolWithTimeout returns a duration used for health-check & stats loops.
const (
	HealthCheckInterval = 30 * time.Second
	StatsInterval       = 60 * time.Second
)
