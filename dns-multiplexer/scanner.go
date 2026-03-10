package main

import (
	"encoding/base32"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ScanResult holds the results of scanning a single resolver.
type ScanResult struct {
	Resolver        Resolver
	Status          string
	LatencyMs       int
	NSSupport       bool
	TXTSupport      bool
	RandomSubdomain bool
	TunnelRealism   bool
	EDNSSupport     bool
	EDNSMax         int
	NXDomainCorrect bool
	Score           int
	Details         string
}

func randLabel(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

func dotifyBase32(payload string, maxLabel int) string {
	var labels []string
	for len(payload) > maxLabel {
		labels = append(labels, payload[:maxLabel])
		payload = payload[maxLabel:]
	}
	if len(payload) > 0 {
		labels = append(labels, payload)
	}
	return strings.Join(labels, ".")
}

func scanSendFn(doh bool) func([]byte, Resolver) ([]byte, error) {
	if doh {
		return func(data []byte, r Resolver) ([]byte, error) {
			return sendQueryDoH(data, r.URL, upstreamTimeout)
		}
	}
	return func(data []byte, r Resolver) ([]byte, error) {
		return sendQueryUDP(data, r.Addr, upstreamTimeout)
	}
}

func buildScanQuery(name string, qtype uint16, ednsPayload uint16) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	if ednsPayload > 0 {
		msg.SetEdns0(ednsPayload, false)
	}
	return msg.Pack()
}

func getRcode(resp []byte) int {
	if len(resp) >= 4 {
		return int(resp[3] & 0x0F)
	}
	return -1
}

func getAncount(resp []byte) int {
	if len(resp) >= 8 {
		return int(resp[6])<<8 | int(resp[7])
	}
	return 0
}

func scanResolver(r Resolver, testDomain string, sendFn func([]byte, Resolver) ([]byte, error)) ScanResult {
	result := ScanResult{
		Resolver: r,
		Status:   "WORKING",
	}

	parts := strings.SplitN(testDomain, ".", 2)
	parentDomain := testDomain
	if len(parts) == 2 {
		parentDomain = parts[1]
	}

	var details []string
	score := 0

	// Test 0: Basic connectivity
	qname := fmt.Sprintf("%s.%s", randLabel(8), parentDomain)
	query, _ := buildScanQuery(qname, dns.TypeA, 0)
	t0 := time.Now()
	resp, err := sendFn(query, r)
	result.LatencyMs = int(time.Since(t0).Milliseconds())
	if err != nil {
		if isTimeout(err) {
			result.Status = "TIMEOUT"
		} else {
			result.Status = "ERROR"
		}
		return result
	}
	if len(resp) < 12 {
		result.Status = "ERROR"
		return result
	}

	// Test 1: NS delegation + glue
	func() {
		defer func() { recover() }()
		query, _ := buildScanQuery(parentDomain, dns.TypeNS, 0)
		resp, err := sendFn(query, r)
		if err != nil || len(resp) < 12 || getRcode(resp) != 0 {
			details = append(details, "NS\u2717")
			return
		}
		query2, _ := buildScanQuery(fmt.Sprintf("ns.%s", parentDomain), dns.TypeA, 0)
		resp2, err := sendFn(query2, r)
		if err == nil && resp2 != nil && getRcode(resp2) == 0 {
			result.NSSupport = true
			score++
			details = append(details, "NS\u2713")
		} else {
			details = append(details, "NS\u2717")
		}
	}()

	// Test 2: TXT record support
	func() {
		defer func() { recover() }()
		qname := fmt.Sprintf("%s.%s", randLabel(8), parentDomain)
		query, _ := buildScanQuery(qname, dns.TypeTXT, 0)
		resp, err := sendFn(query, r)
		if err == nil && len(resp) >= 12 {
			result.TXTSupport = true
			score++
			details = append(details, "TXT\u2713")
		} else {
			details = append(details, "TXT\u2717")
		}
	}()

	// Test 3: Random nested subdomain
	func() {
		defer func() { recover() }()
		passed := false
		for i := 0; i < 2; i++ {
			qname := fmt.Sprintf("%s.%s.%s", randLabel(8), randLabel(8), testDomain)
			query, _ := buildScanQuery(qname, dns.TypeA, 0)
			resp, err := sendFn(query, r)
			if err == nil && len(resp) >= 12 {
				passed = true
				break
			}
		}
		result.RandomSubdomain = passed
		if passed {
			score++
			details = append(details, "RND\u2713")
		} else {
			details = append(details, "RND\u2717")
		}
	}()

	// Test 4: Tunnel realism (DPI evasion)
	func() {
		defer func() { recover() }()
		payload := make([]byte, 100)
		for i := range payload {
			payload[i] = byte(rand.Intn(256))
		}
		b32 := strings.ToLower(strings.TrimRight(
			base32.StdEncoding.EncodeToString(payload), "="))
		dotified := dotifyBase32(b32, 57)
		qname := fmt.Sprintf("%s.%s", dotified, testDomain)
		query, _ := buildScanQuery(qname, dns.TypeTXT, 0)
		resp, err := sendFn(query, r)
		if err == nil && len(resp) >= 12 {
			result.TunnelRealism = true
			score++
			details = append(details, "DPI\u2713")
		} else {
			details = append(details, "DPI\u2717")
		}
	}()

	// Test 5: EDNS0 payload size
	func() {
		defer func() { recover() }()
		maxEdns := 0
		for _, size := range []uint16{512, 900, 1232} {
			qname := fmt.Sprintf("%s.%s", randLabel(8), testDomain)
			query, _ := buildScanQuery(qname, dns.TypeTXT, size)
			resp, err := sendFn(query, r)
			if err == nil && len(resp) >= 12 && getRcode(resp) != 1 {
				maxEdns = int(size)
			} else {
				break
			}
		}
		result.EDNSMax = maxEdns
		if maxEdns > 0 {
			result.EDNSSupport = true
			score++
			details = append(details, fmt.Sprintf("EDNS\u2713(%d)", maxEdns))
		} else {
			details = append(details, "EDNS\u2717")
		}
	}()

	// Test 6: NXDOMAIN correctness
	func() {
		defer func() { recover() }()
		nxCorrect := 0
		for i := 0; i < 3; i++ {
			qname := fmt.Sprintf("nxd-%s.invalid", randLabel(8))
			query, _ := buildScanQuery(qname, dns.TypeA, 0)
			resp, err := sendFn(query, r)
			if err != nil {
				continue
			}
			rcode := getRcode(resp)
			if rcode == 3 { // NXDOMAIN
				nxCorrect++
			} else if rcode == 0 && getAncount(resp) == 0 {
				nxCorrect++ // acceptable
			}
		}
		if nxCorrect >= 2 {
			result.NXDomainCorrect = true
			score++
			details = append(details, "NXD\u2713")
		} else {
			details = append(details, "NXD\u2717")
		}
	}()

	result.Score = score
	result.Details = strings.Join(details, " ")
	return result
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(interface{ Timeout() bool }); ok {
		return ne.Timeout()
	}
	return strings.Contains(err.Error(), "timeout")
}

func runScan(resolvers []Resolver, testDomain string, doh bool, workers int) []ScanResult {
	sendFn := scanSendFn(doh)

	modeStr := "UDP"
	if doh {
		modeStr = "DoH (HTTPS)"
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 78))
	fmt.Printf("  DNS Tunnel Compatibility Scanner\n")
	fmt.Printf("  Test domain: %s\n", testDomain)
	fmt.Printf("  Mode: %s\n", modeStr)
	fmt.Printf("  Resolvers: %d\n", len(resolvers))
	fmt.Printf("%s\n\n", strings.Repeat("=", 78))

	var (
		mu      sync.Mutex
		results []ScanResult
		wg      sync.WaitGroup
	)

	sem := make(chan struct{}, workers)
	for _, r := range resolvers {
		wg.Add(1)
		sem <- struct{}{}
		go func(r Resolver) {
			defer func() {
				<-sem
				wg.Done()
			}()

			result := scanResolver(r, testDomain, sendFn)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			label := r.String()
			var status string
			switch result.Status {
			case "WORKING":
				status = "\033[32mWORKING\033[0m"
			case "TIMEOUT":
				status = "\033[33mTIMEOUT\033[0m"
			default:
				status = fmt.Sprintf("\033[31m%s\033[0m", result.Status)
			}

			fmt.Printf("  %-45s %-18s %4dms  Score: %d/6  %s\n",
				label, status, result.LatencyMs, result.Score, result.Details)
		}(r)
	}
	wg.Wait()

	// Summary
	var working, timeouts, errors int
	for _, r := range results {
		switch r.Status {
		case "WORKING":
			working++
		case "TIMEOUT":
			timeouts++
		default:
			errors++
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("\u2500", 78))
	fmt.Printf("  Total: %d  |  \033[32mWorking: %d\033[0m  |  \033[33mTimeout: %d\033[0m  |  \033[31mError: %d\033[0m\n",
		len(results), working, timeouts, errors)

	if working > 0 {
		// Sort by score desc, latency asc
		best := make([]ScanResult, 0, working)
		for _, r := range results {
			if r.Status == "WORKING" {
				best = append(best, r)
			}
		}
		// Simple insertion sort for top 5
		for i := 1; i < len(best); i++ {
			for j := i; j > 0; j-- {
				if best[j].Score > best[j-1].Score ||
					(best[j].Score == best[j-1].Score && best[j].LatencyMs < best[j-1].LatencyMs) {
					best[j], best[j-1] = best[j-1], best[j]
				}
			}
		}
		fmt.Printf("\n  Best resolvers for tunneling:\n")
		limit := 5
		if len(best) < limit {
			limit = len(best)
		}
		for _, r := range best[:limit] {
			fmt.Printf("    %-45s Score: %d/6  %dms  %s\n",
				r.Resolver.String(), r.Score, r.LatencyMs, r.Details)
		}
	}

	fmt.Println()
	return results
}
