package main

import (
	"log/slog"
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

var coverDomains = []string{
	"google.com", "microsoft.com", "apple.com", "amazon.com",
	"cloudflare.com", "facebook.com", "github.com", "wikipedia.org",
	"yahoo.com", "bing.com", "reddit.com", "twitter.com",
	"linkedin.com", "netflix.com", "instagram.com", "whatsapp.com",
}

// CoverTraffic generates periodic legitimate DNS queries to blend tunnel traffic.
type CoverTraffic struct {
	pool     *ResolverPool
	minDelay time.Duration
	maxDelay time.Duration
	done     chan struct{}
}

func NewCoverTraffic(pool *ResolverPool, minSec, maxSec float64) *CoverTraffic {
	return &CoverTraffic{
		pool:     pool,
		minDelay: time.Duration(minSec * float64(time.Second)),
		maxDelay: time.Duration(maxSec * float64(time.Second)),
		done:     make(chan struct{}),
	}
}

func (c *CoverTraffic) Start() {
	slog.Info("Cover traffic enabled", "min", c.minDelay, "max", c.maxDelay)
	go c.loop()
}

func (c *CoverTraffic) loop() {
	for {
		select {
		case <-c.done:
			return
		default:
		}

		domain := coverDomains[rand.Intn(len(coverDomains))]
		resolver := c.pool.GetNext()

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		msg.RecursionDesired = true
		query, err := msg.Pack()
		if err == nil {
			_, err = c.pool.SendQuery(query, resolver)
			if err == nil {
				slog.Debug("Cover query", "domain", domain, "resolver", resolver)
			}
		}

		delay := c.minDelay + time.Duration(rand.Float64()*float64(c.maxDelay-c.minDelay))
		select {
		case <-c.done:
			return
		case <-time.After(delay):
		}
	}
}

func (c *CoverTraffic) Stop() {
	close(c.done)
}
