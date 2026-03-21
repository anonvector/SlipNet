package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DNS record types
const (
	dnsTypeA   = 1
	dnsTypeNS  = 2
	dnsTypeTXT = 16
	dnsTypeOPT = 41
)

// Scanner result status
const (
	statusWorking = "WORKING"
	statusTimeout = "TIMEOUT"
	statusError   = "ERROR"
)

// TunnelTestResult holds detailed DNS tunnel compatibility results.
type TunnelTestResult struct {
	NSSupport      bool
	TXTSupport     bool
	RandomSub      bool
	TunnelRealism  bool
	EDNS0Support   bool
	EDNSMaxPayload int
	NXDOMAINCorrect bool
}

func (t *TunnelTestResult) Score() int {
	n := 0
	for _, b := range []bool{t.NSSupport, t.TXTSupport, t.RandomSub, t.TunnelRealism, t.EDNS0Support, t.NXDOMAINCorrect} {
		if b {
			n++
		}
	}
	return n
}

func (t *TunnelTestResult) Details() string {
	f := func(ok bool, label string) string {
		if ok {
			return label + "✓"
		}
		return label + "✗"
	}
	edns := f(t.EDNS0Support, "EDNS")
	if t.EDNS0Support && t.EDNSMaxPayload > 0 {
		edns += fmt.Sprintf("(%d)", t.EDNSMaxPayload)
	}
	return fmt.Sprintf("%s %s %s %s %s %s",
		f(t.NSSupport, "NS→A"), f(t.TXTSupport, "TXT"), f(t.RandomSub, "RND"),
		f(t.TunnelRealism, "DPI"), edns, f(t.NXDOMAINCorrect, "NXD"))
}

// ScanResult holds the result of scanning one resolver.
type ScanResult struct {
	Host       string
	Port       int
	Status     string
	LatencyMs  int64
	Error      string
	Tunnel     *TunnelTestResult
}

// ScanResolvers scans a list of resolver IPs concurrently.
// querySize caps the tunnel-realism probe to match the user's --query-size (0 = full capacity).
func ScanResolvers(resolvers []string, port int, testDomain string, timeoutMs int, concurrency int, querySize int, onResult func(ScanResult)) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range resolvers {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			result := scanResolver(host, port, testDomain, timeoutMs, querySize)
			onResult(result)
		}(ip)
	}
	wg.Wait()
}

func scanResolver(host string, port int, testDomain string, timeoutMs int, querySize int) ScanResult {
	result := ScanResult{Host: host, Port: port}

	start := time.Now()
	sub := randomLabel(8)
	parent := getParentDomain(testDomain)
	query := sub + "." + parent

	// Use shorter timeout for initial probe — if a resolver can't answer
	// a basic A query quickly, it's too slow for tunneling anyway.
	probeTimeout := timeoutMs
	if probeTimeout > 1500 {
		probeTimeout = 1500
	}
	resp, err := dnsQuery(host, port, query, dnsTypeA, probeTimeout, nil)
	latency := time.Since(start).Milliseconds()
	result.LatencyMs = latency

	if err != nil {
		if isTimeout(err) {
			result.Status = statusTimeout
		} else {
			result.Status = statusError
			result.Error = err.Error()
		}
		return result
	}
	if resp == nil {
		result.Status = statusTimeout
		return result
	}

	result.Status = statusWorking
	tunnel := &TunnelTestResult{}

	// Run all tunnel tests concurrently for speed
	var twg sync.WaitGroup
	twg.Add(6)
	go func() { defer twg.Done(); tunnel.NSSupport = testNS(host, port, parent, timeoutMs) }()
	go func() { defer twg.Done(); tunnel.TXTSupport = testTXT(host, port, testDomain, timeoutMs) }()
	go func() { defer twg.Done(); tunnel.RandomSub = testRandomSubdomain(host, port, testDomain, timeoutMs) }()
	go func() { defer twg.Done(); tunnel.TunnelRealism = testTunnelRealism(host, port, testDomain, timeoutMs, querySize) }()
	go func() {
		defer twg.Done()
		tunnel.EDNS0Support, tunnel.EDNSMaxPayload = testEDNS0(host, port, testDomain, timeoutMs)
	}()
	go func() { defer twg.Done(); tunnel.NXDOMAINCorrect = testNXDOMAIN(host, port, timeoutMs) }()
	twg.Wait()

	result.Tunnel = tunnel
	return result
}

// --- Individual tests ---

func testNS(host string, port int, parentDomain string, timeoutMs int) bool {
	resp, err := dnsQuery(host, port, parentDomain, dnsTypeNS, timeoutMs, nil)
	if err != nil || resp == nil {
		return false
	}
	nsHost := extractNSHost(resp)
	if nsHost == "" {
		return false
	}
	// Resolve the NS hostname via A record
	resp2, err := dnsQuery(host, port, nsHost, dnsTypeA, timeoutMs, nil)
	return err == nil && resp2 != nil
}

func testTXT(host string, port int, testDomain string, timeoutMs int) bool {
	sub := randomLabel(8)
	parent := getParentDomain(testDomain)
	resp, err := dnsQuery(host, port, sub+"."+parent, dnsTypeTXT, timeoutMs, nil)
	return err == nil && resp != nil
}

func testRandomSubdomain(host string, port int, testDomain string, timeoutMs int) bool {
	for i := 0; i < 2; i++ {
		sub := randomLabel(8) + "." + randomLabel(8)
		resp, err := dnsQuery(host, port, sub+"."+testDomain, dnsTypeA, timeoutMs, nil)
		if err == nil && resp != nil {
			return true
		}
	}
	return false
}

func testTunnelRealism(host string, port int, testDomain string, timeoutMs int, querySize int) bool {
	// Generate random bytes, base32-encode, split into 57-char DNS labels.
	// When querySize is set, scale the random payload down so the total
	// wire-format query stays within the budget.
	randLen := 100 // default: full-capacity probe
	if querySize >= 50 {
		// Approximate overhead: 12-byte header + 4-byte qtype/qclass + domain suffix + label length bytes.
		// Estimate usable payload bytes conservatively.
		suffixLen := len(testDomain) + 2 // "." separator + root label
		overhead := 12 + 4 + suffixLen
		available := querySize - overhead
		if available < 10 {
			available = 10
		}
		// base32 expands 5 bytes → 8 chars; labels add 1 length byte per 57 chars.
		// Solve for raw bytes: chars = ceil(raw*8/5), wire ≈ chars + chars/57
		// Simplify: raw ≈ available * 5 / 9
		randLen = available * 5 / 9
		if randLen < 5 {
			randLen = 5
		}
		if randLen > 100 {
			randLen = 100
		}
	}
	randBytes := make([]byte, randLen)
	for i := range randBytes {
		randBytes[i] = byte(rand.IntN(256))
	}
	encoded := base32Encode(randBytes)
	labels := splitLabels(encoded, 57)
	query := strings.Join(labels, ".") + "." + testDomain

	resp, err := dnsQuery(host, port, query, dnsTypeTXT, timeoutMs, nil)
	return err == nil && resp != nil
}

func testEDNS0(host string, port int, testDomain string, timeoutMs int) (bool, int) {
	sizes := []int{512, 900, 1232}
	maxPayload := 0
	anyOK := false
	for _, size := range sizes {
		sub := randomLabel(8)
		parent := getParentDomain(testDomain)
		query := sub + "." + parent

		edns := buildEDNS0OPT(size)
		resp, err := dnsQuery(host, port, query, dnsTypeA, timeoutMs, edns)
		if err != nil || resp == nil {
			break
		}
		// Check if response contains OPT record and RCODE != FORMERR(1)
		rcode := int(resp[3]) & 0x0F
		if rcode == 1 { // FORMERR
			break
		}
		if hasOPTRecord(resp) {
			anyOK = true
			maxPayload = size
		} else {
			break
		}
	}
	return anyOK, maxPayload
}

func testNXDOMAIN(host string, port int, timeoutMs int) bool {
	good := 0
	for i := 0; i < 3; i++ {
		sub := randomLabel(12)
		query := sub + ".invalid"
		resp, err := dnsQuery(host, port, query, dnsTypeA, timeoutMs, nil)
		if err != nil || resp == nil {
			continue
		}
		rcode := int(resp[3]) & 0x0F
		if rcode == 3 { // NXDOMAIN
			good++
		}
	}
	return good >= 2
}

// DetectTransparentProxy tests if the ISP intercepts DNS queries
// by sending queries to RFC 5737 TEST-NET IPs that should never host DNS servers.
func DetectTransparentProxy(testDomain string, timeoutMs int) bool {
	testNets := []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}
	var detected atomic.Bool
	var wg sync.WaitGroup
	for _, ip := range testNets {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sub := randomLabel(8)
			resp, err := dnsQuery(ip, 53, sub+"."+testDomain, dnsTypeA, timeoutMs, nil)
			if err == nil && resp != nil {
				detected.Store(true)
			}
		}(ip)
	}
	wg.Wait()
	return detected.Load()
}

// --- DNS packet construction & parsing ---

func dnsQuery(host string, port int, name string, qtype uint16, timeoutMs int, additional []byte) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", addr, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))

	// Build query packet
	txid := []byte{byte(rand.IntN(256)), byte(rand.IntN(256))}

	var pkt []byte
	pkt = append(pkt, txid...)
	pkt = append(pkt, 0x01, 0x00) // flags: RD=1
	pkt = append(pkt, 0x00, 0x01) // questions: 1
	pkt = append(pkt, 0x00, 0x00) // answers: 0
	pkt = append(pkt, 0x00, 0x00) // authority: 0
	if additional != nil {
		pkt = append(pkt, 0x00, 0x01) // additional: 1
	} else {
		pkt = append(pkt, 0x00, 0x00) // additional: 0
	}

	// Encode domain name
	pkt = append(pkt, encodeDNSName(name)...)
	// QTYPE + QCLASS
	pkt = append(pkt, byte(qtype>>8), byte(qtype))
	pkt = append(pkt, 0x00, 0x01) // IN class

	// Additional section (EDNS0 OPT)
	if additional != nil {
		pkt = append(pkt, additional...)
	}

	_, err = conn.Write(pkt)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func encodeDNSName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00)
	return out
}

func buildEDNS0OPT(payloadSize int) []byte {
	// OPT pseudo-RR: name=root(0), type=OPT(41), class=payloadSize, TTL=0, rdlen=0
	return []byte{
		0x00,                                      // root name
		0x00, byte(dnsTypeOPT),                    // type OPT (41)
		byte(payloadSize >> 8), byte(payloadSize), // UDP payload size
		0x00, 0x00, 0x00, 0x00,                    // extended RCODE + version + flags
		0x00, 0x00,                                // RDLENGTH = 0
	}
}

func hasOPTRecord(resp []byte) bool {
	if len(resp) < 12 {
		return false
	}
	// Scan additional section for OPT (type 41)
	arcount := int(binary.BigEndian.Uint16(resp[10:12]))
	if arcount == 0 {
		return false
	}
	// Skip header (12) + question + answer + authority sections
	offset := 12
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	nscount := int(binary.BigEndian.Uint16(resp[8:10]))

	// Skip question section
	for i := 0; i < qdcount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		offset += 4 // QTYPE + QCLASS
	}
	// Skip answer + authority sections
	for i := 0; i < ancount+nscount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return false
		}
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10 + rdlen
	}
	// Scan additional section
	for i := 0; i < arcount && offset < len(resp); i++ {
		nameEnd := skipDNSName(resp, offset)
		if nameEnd+10 > len(resp) {
			return false
		}
		rtype := binary.BigEndian.Uint16(resp[nameEnd : nameEnd+2])
		if rtype == dnsTypeOPT {
			return true
		}
		rdlen := int(binary.BigEndian.Uint16(resp[nameEnd+8 : nameEnd+10]))
		offset = nameEnd + 10 + rdlen
	}
	return false
}

func extractNSHost(resp []byte) string {
	if len(resp) < 12 {
		return ""
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	offset := 12
	// Skip question section
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdcount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		offset += 4
	}
	// Read first NS answer
	for i := 0; i < ancount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return ""
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if rtype == dnsTypeNS && rdlen > 0 && offset+rdlen <= len(resp) {
			return decodeDNSName(resp, offset)
		}
		offset += rdlen
	}
	return ""
}

func skipDNSName(pkt []byte, offset int) int {
	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			return offset + 1
		}
		if length >= 0xC0 { // pointer
			return offset + 2
		}
		offset += 1 + length
	}
	return offset
}

func decodeDNSName(pkt []byte, offset int) string {
	var parts []string
	visited := make(map[int]bool)
	for offset < len(pkt) {
		if visited[offset] {
			break // prevent loops
		}
		visited[offset] = true
		length := int(pkt[offset])
		if length == 0 {
			break
		}
		if length >= 0xC0 {
			if offset+1 >= len(pkt) {
				break
			}
			ptr := int(pkt[offset]&0x3F)<<8 | int(pkt[offset+1])
			offset = ptr
			continue
		}
		offset++
		if offset+length > len(pkt) {
			break
		}
		parts = append(parts, string(pkt[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, ".")
}

// --- Utilities ---

func getParentDomain(domain string) string {
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) >= 2 && strings.Contains(parts[1], ".") {
		return parts[1]
	}
	return domain
}

func randomLabel(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.IntN(len(chars))]
	}
	return string(b)
}

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func base32Encode(data []byte) string {
	var sb strings.Builder
	buf := uint64(0)
	bits := 0
	for _, b := range data {
		buf = (buf << 8) | uint64(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			idx := (buf >> uint(bits)) & 0x1F
			sb.WriteByte(base32Alphabet[idx])
		}
	}
	if bits > 0 {
		idx := (buf << uint(5-bits)) & 0x1F
		sb.WriteByte(base32Alphabet[idx])
	}
	return sb.String()
}

func splitLabels(s string, maxLen int) []string {
	var labels []string
	for len(s) > maxLen {
		labels = append(labels, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		labels = append(labels, s)
	}
	return labels
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// --- Verification scan ---

// verifyBase32 is the lowercase base32 alphabet matching dnstt/noizdns
// subdomain encoding, so probes are visually indistinguishable from real traffic.
var verifyBase32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// testVerify probes a resolver using the slipgate HMAC challenge-response protocol.
//
// Query format:  <base32(nonce[16] || HMAC(key,nonce)[:16])>.<domain>  (TXT)
// Response:      TXT containing raw HMAC(key, nonce||0x01) (32 bytes), possibly padded.
//
// The probe encodes a client proof so the server only replies when the key matches.
func testVerify(host string, port int, testDomain string, timeoutMs int, pubkey []byte, responseSize int) bool {
	// Generate random 16-byte nonce
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(rand.IntN(256))
	}

	// Encode desired response size in nonce[14:16] so the server can read it
	// directly from the probe, bypassing resolver EDNS0 rewriting.
	// Zero means "use server default" — always write this field explicitly
	// so random nonce bytes don't accidentally look like a valid size.
	if responseSize > 0 {
		binary.BigEndian.PutUint16(nonce[14:16], uint16(responseSize))
	} else {
		nonce[14] = 0
		nonce[15] = 0
	}

	// Compute client proof: HMAC-SHA256(pubkey, nonce)[:16]
	mac := hmac.New(sha256.New, pubkey)
	mac.Write(nonce)
	proof := mac.Sum(nil)[:16]

	// Encode nonce || proof as lowercase base32 (no padding) → 52 chars
	encoded := verifyBase32.EncodeToString(append(nonce, proof...))

	// Query: <encoded>.<testDomain>
	// Include EDNS0 OPT to advertise UDP payload size. Clamp to at least 1232
	// (dnsflagday standard) so resolvers don't truncate the response before it
	// reaches us — the actual desired size is encoded in the nonce above.
	ednsSize := 1232
	if responseSize > 1232 {
		ednsSize = responseSize
	}
	resp, err := dnsQuery(host, port, encoded+"."+testDomain, dnsTypeTXT, timeoutMs, buildEDNS0OPT(ednsSize))
	if err != nil || resp == nil {
		return false
	}

	if len(resp) < 12 {
		return false
	}
	if int(resp[3])&0x0F != 0 {
		return false
	}

	// Server returns raw binary HMAC in TXT record (32 bytes + optional padding)
	rawData := extractTXTRawData(resp)
	if len(rawData) < 32 {
		return false
	}

	// Verify: expected = HMAC-SHA256(pubkey, nonce || 0x01)
	mac2 := hmac.New(sha256.New, pubkey)
	mac2.Write(nonce)
	mac2.Write([]byte{0x01})
	return hmac.Equal(rawData[:32], mac2.Sum(nil))
}

// extractTXTRawData extracts the raw binary data from the first TXT answer
// record in a DNS response (concatenates all character-strings as bytes).
func extractTXTRawData(resp []byte) []byte {
	if len(resp) < 12 {
		return nil
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		return nil
	}

	offset := 12
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdcount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		offset += 4 // QTYPE + QCLASS
	}

	for i := 0; i < ancount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return nil
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if rtype == dnsTypeTXT && rdlen > 0 && offset+rdlen <= len(resp) {
			var data []byte
			end := offset + rdlen
			for offset < end {
				strLen := int(resp[offset])
				offset++
				if offset+strLen > end {
					break
				}
				data = append(data, resp[offset:offset+strLen]...)
				offset += strLen
			}
			return data
		}
		offset += rdlen
	}
	return nil
}

// extractTXTData extracts the concatenated TXT character-strings from
// the first TXT answer record in a DNS response.
func extractTXTData(resp []byte) string {
	if len(resp) < 12 {
		return ""
	}
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		return ""
	}

	offset := 12
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdcount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		offset += 4 // QTYPE + QCLASS
	}

	for i := 0; i < ancount && offset < len(resp); i++ {
		offset = skipDNSName(resp, offset)
		if offset+10 > len(resp) {
			return ""
		}
		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(resp[offset+8 : offset+10]))
		offset += 10
		if rtype == dnsTypeTXT && rdlen > 0 && offset+rdlen <= len(resp) {
			var sb strings.Builder
			end := offset + rdlen
			for offset < end {
				strLen := int(resp[offset])
				offset++
				if offset+strLen > end {
					break
				}
				sb.Write(resp[offset : offset+strLen])
				offset += strLen
			}
			return sb.String()
		}
		offset += rdlen
	}
	return ""
}

// RunVerifyScanner sends HMAC-authenticated verification probes to each
// resolver. Each resolver gets probeCount probes and must pass at least
// passThreshold to be considered verified. Results are shown in real time.
func RunVerifyScanner(resolvers []string, testDomain string, port int, timeoutMs int, concurrency int, probeCount int, passThreshold int, pubkey []byte, responseSize int) {
	if probeCount <= 0 {
		probeCount = 20
	}
	if passThreshold <= 0 || passThreshold > probeCount {
		passThreshold = probeCount / 4
		if passThreshold < 1 {
			passThreshold = 1
		}
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║              SlipNet Prism                       ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Domain:      %s\n", testDomain)
	fmt.Printf("  Resolvers:   %d\n", len(resolvers))
	fmt.Printf("  Probes:      %d (pass: %d/%d)\n", probeCount, passThreshold, probeCount)
	fmt.Printf("  Concurrency: %d\n", concurrency)
	fmt.Printf("  Timeout:     %dms\n", timeoutMs)
	if responseSize > 0 {
		fmt.Printf("  Resp. size:  %d bytes\n", responseSize)
	}
	fmt.Println()

	// Graceful stop on Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var stopped atomic.Bool
	go func() {
		<-sigCh
		stopped.Store(true)
		fmt.Printf("\n\n  Scan interrupted! Finishing in-flight tests...\n")
		fmt.Println("  Press Ctrl+C again to force exit.")
		<-sigCh
		os.Exit(1)
	}()

	startTime := time.Now()
	total := int64(len(resolvers))
	var scanned int64
	var verified int64
	var verifiedIPs []string
	var mu sync.Mutex

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, ip := range resolvers {
		if stopped.Load() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		if stopped.Load() {
			<-sem
			wg.Done()
			break
		}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			if stopped.Load() {
				return
			}

			// Run probes with early exit
			passed := 0
			maxFailures := probeCount - passThreshold
			failures := 0
			for i := 0; i < probeCount; i++ {
				if stopped.Load() {
					return
				}
				if testVerify(host, port, testDomain, timeoutMs, pubkey, responseSize) {
					passed++
					if passed >= passThreshold {
						break // already verified
					}
				} else {
					failures++
					if failures > maxFailures {
						break
					}
				}
			}

			n := atomic.AddInt64(&scanned, 1)
			if passed >= passThreshold {
				atomic.AddInt64(&verified, 1)
				mu.Lock()
				verifiedIPs = append(verifiedIPs, host)
				mu.Unlock()
				v := atomic.LoadInt64(&verified)
				fmt.Printf("\r  ✓ %-18s  %d/%d probes        (verified: %d)\n", host, passed, probeCount, v)
				fmt.Printf("  Scanning... %d/%d  (verified: %d)", n, total, v)
			} else if n%20 == 0 || n == total {
				v := atomic.LoadInt64(&verified)
				fmt.Printf("\r  Scanning... %d/%d  (verified: %d)", n, total, v)
			}
		}(ip)
	}

	wg.Wait()
	signal.Stop(sigCh)

	elapsed := time.Since(startTime)
	s := atomic.LoadInt64(&scanned)
	v := atomic.LoadInt64(&verified)
	fmt.Printf("\r  Scanning... %d/%d  (verified: %d)\n", s, total, v)
	fmt.Println()

	fmt.Println("  ── Verified Resolvers ────────────────────────────")
	fmt.Println()
	if stopped.Load() {
		fmt.Printf("  Scanned: %d/%d (interrupted)\n", s, total)
	}
	fmt.Printf("  %d/%d resolvers verified (%s)\n",
		len(verifiedIPs), len(resolvers), elapsed.Round(time.Millisecond))
	fmt.Println()

	for _, ip := range verifiedIPs {
		fmt.Printf("  %s\n", ip)
	}
	fmt.Println()

	// Save prompt
	if len(verifiedIPs) > 0 {
		if reader == nil {
			reader = bufio.NewReader(os.Stdin)
		}
		fmt.Print("  Save results to file? (Y/n): ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))
		if choice != "n" && choice != "no" {
			filename := "verified.txt"
			content := strings.Join(verifiedIPs, "\n") + "\n"
			if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
				fmt.Printf("  Error saving: %v\n", err)
			} else {
				fmt.Printf("  Saved %d verified IPs to %s\n", len(verifiedIPs), filename)
			}
			fmt.Println()
		}
	}
}

// LoadIPList parses a text file/string into a list of IP addresses.
func LoadIPList(content string) []string {
	var ips []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Extract IP (take first token, strip port if present)
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		ip := strings.Split(parts[0], ":")[0]
		ip = strings.TrimSpace(ip)
		if net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

// RunScanner is the main entry point for the CLI scanner.
// If e2eConfig is non-nil, E2E tests run in parallel as 6/6 resolvers are found.
// querySize caps DNS probes to match the user's --query-size (0 = full capacity).
func RunScanner(resolvers []string, testDomain string, port int, timeoutMs int, concurrency int, querySize int, e2eConfig *E2EConfig) {
	total := len(resolvers)
	var scanned int64
	var working int64
	var timeouts int64
	var errors int64

	type scoredResult struct {
		ScanResult
		score int
	}
	var mu sync.Mutex
	var compatible []scoredResult
	var workingIPs []string

	// E2E state (parallel pipeline)
	var e2eChan chan string
	var e2eWg sync.WaitGroup
	var e2eTested int64
	var e2ePassed int64
	var e2eMu sync.Mutex
	var e2eResults []E2EResult
	var e2ePassedIPs []string
	var portCounter int32 = 19000

	// Print mutex for clean terminal output
	var printMu sync.Mutex

	// Graceful stop on Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var stopped atomic.Bool

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Println("║              SlipNet DNS Scanner                 ║")
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Domain:      %s\n", testDomain)
	fmt.Printf("  Resolvers:   %d\n", total)
	fmt.Printf("  Concurrency: %d\n", concurrency)
	fmt.Printf("  Timeout:     %dms\n", timeoutMs)
	if querySize > 0 {
		fmt.Printf("  Query Size:  %d bytes\n", querySize)
	}
	if e2eConfig != nil {
		mode := "DNSTT"
		if e2eConfig.NoizMode {
			mode = "NoizDNS"
		}
		if e2eConfig.SSHMode {
			mode += "+SSH"
		}
		fmt.Printf("  E2E:         enabled (%s, concurrency: %d)\n", mode, e2eConfig.Concurrency)
	}
	fmt.Println()

	// Transparent proxy detection
	fmt.Print("  Checking for transparent DNS proxy... ")
	if DetectTransparentProxy(testDomain, 2000) {
		fmt.Println("DETECTED")
		fmt.Println("  ⚠ Your ISP intercepts DNS queries. Results may be inaccurate.")
	} else {
		fmt.Println("not detected")
	}
	fmt.Println()

	startTime := time.Now()

	// Start E2E worker pool (runs in parallel with scanning)
	if e2eConfig != nil {
		// Suppress noizdns tunnel library logging during E2E
		log.SetOutput(io.Discard)
		e2eChan = make(chan string, 200)
		e2eConcurrency := e2eConfig.Concurrency
		if e2eConcurrency <= 0 {
			e2eConcurrency = 10
		}
		for i := 0; i < e2eConcurrency; i++ {
			e2eWg.Add(1)
			go func() {
				defer e2eWg.Done()
				for ip := range e2eChan {
					if stopped.Load() {
						continue
					}
					p := allocatePort(&portCounter)
					if p == 0 {
						continue
					}
					result := testResolverE2E(ip, p, *e2eConfig)
					n := atomic.AddInt64(&e2eTested, 1)

					e2eMu.Lock()
					e2eResults = append(e2eResults, result)
					if result.Success {
						atomic.AddInt64(&e2ePassed, 1)
						e2ePassedIPs = append(e2ePassedIPs, result.Host)
					}
					e2eMu.Unlock()

					ep := atomic.LoadInt64(&e2ePassed)
					printMu.Lock()
					if result.Success {
						fmt.Printf("\r  ✓ E2E %-18s PASS  %5dms        (E2E: %d/%d)\n", result.Host, result.TotalMs, ep, n)
					}
					s := atomic.LoadInt64(&scanned)
					w := atomic.LoadInt64(&working)
					fmt.Printf("  Scanning... %d/%d  (working: %d)  |  E2E: %d/%d passed", s, total, w, ep, n)
					printMu.Unlock()
				}
			}()
		}
	}

	// Handle Ctrl+C — first press stops scan, second press force-exits
	go func() {
		<-sigCh
		stopped.Store(true)
		printMu.Lock()
		fmt.Printf("\n\n  Scan interrupted! Finishing in-flight tests...\n")
		fmt.Println("  Press Ctrl+C again to force exit.")
		printMu.Unlock()
		<-sigCh
		os.Exit(1)
	}()

	// Scan resolvers (inline for stop support + E2E feeding)
	sem := make(chan struct{}, concurrency)
	var scanWg sync.WaitGroup

	for _, ip := range resolvers {
		if stopped.Load() {
			break
		}
		scanWg.Add(1)
		sem <- struct{}{}
		if stopped.Load() {
			<-sem
			scanWg.Done()
			break
		}
		go func(host string) {
			defer scanWg.Done()
			defer func() { <-sem }()

			if stopped.Load() {
				return
			}

			result := scanResolver(host, port, testDomain, timeoutMs, querySize)
			n := atomic.AddInt64(&scanned, 1)

			switch result.Status {
			case statusWorking:
				atomic.AddInt64(&working, 1)
			case statusTimeout:
				atomic.AddInt64(&timeouts, 1)
			case statusError:
				atomic.AddInt64(&errors, 1)
			}

			if result.Tunnel != nil && result.Tunnel.Score() > 0 {
				mu.Lock()
				compatible = append(compatible, scoredResult{result, result.Tunnel.Score()})
				if result.Tunnel.Score() == 6 {
					workingIPs = append(workingIPs, host)
					if e2eChan != nil && !stopped.Load() {
						select {
						case e2eChan <- host:
						default:
						}
					}
				}
				mu.Unlock()
			}

			// Progress update
			if n%10 == 0 || n == int64(total) || (result.Tunnel != nil && result.Tunnel.Score() == 6) {
				printMu.Lock()
				w := atomic.LoadInt64(&working)
				if e2eConfig != nil {
					ep := atomic.LoadInt64(&e2ePassed)
					et := atomic.LoadInt64(&e2eTested)
					fmt.Printf("\r  Scanning... %d/%d  (working: %d)  |  E2E: %d/%d passed", n, total, w, ep, et)
				} else {
					fmt.Printf("\r  Scanning... %d/%d  (working: %d)", n, total, w)
				}
				printMu.Unlock()
			}
		}(ip)
	}

	scanWg.Wait()

	// Close E2E channel and wait for remaining tests
	if e2eChan != nil {
		close(e2eChan)
		remaining := len(workingIPs) - int(atomic.LoadInt64(&e2eTested))
		if remaining > 0 && !stopped.Load() {
			printMu.Lock()
			fmt.Printf("\n  DNS scan complete. Waiting for %d remaining E2E tests...\n", remaining)
			printMu.Unlock()
		}
		e2eWg.Wait()
		log.SetOutput(os.Stderr)
	}

	signal.Stop(sigCh)

	elapsed := time.Since(startTime)

	// Final progress line
	s := atomic.LoadInt64(&scanned)
	w := atomic.LoadInt64(&working)
	t := atomic.LoadInt64(&timeouts)
	e := atomic.LoadInt64(&errors)
	if e2eConfig != nil {
		ep := atomic.LoadInt64(&e2ePassed)
		et := atomic.LoadInt64(&e2eTested)
		fmt.Printf("\r  Scanning... %d/%d  (working: %d)  |  E2E: %d/%d passed\n", s, total, w, ep, et)
	} else {
		fmt.Printf("\r  Scanning... %d/%d  (working: %d)\n", s, total, w)
	}
	fmt.Println()

	// Sort by score descending, then by latency ascending
	for i := 0; i < len(compatible); i++ {
		for j := i + 1; j < len(compatible); j++ {
			if compatible[j].score > compatible[i].score ||
				(compatible[j].score == compatible[i].score && compatible[j].LatencyMs < compatible[i].LatencyMs) {
				compatible[i], compatible[j] = compatible[j], compatible[i]
			}
		}
	}

	// Print results
	fmt.Println("  ── Results ──────────────────────────────────────")
	fmt.Println()
	if stopped.Load() {
		fmt.Printf("  Scanned: %d/%d (interrupted)\n", s, total)
	}
	fmt.Printf("  Total: %d | Working: %d | Timeout: %d | Error: %d\n",
		s, w, t, e)
	fmt.Printf("  Elapsed: %s\n", elapsed.Round(time.Millisecond))
	fmt.Println()

	if len(compatible) == 0 {
		fmt.Println("  No compatible resolvers found.")
		saveResultsPrompt(workingIPs, e2ePassedIPs)
		return
	}

	// Print compatible resolvers
	fmt.Printf("  Compatible resolvers (%d):\n\n", len(compatible))
	fmt.Printf("  %-18s %5s  %5s  %s\n", "RESOLVER", "SCORE", "MS", "DETAILS")
	fmt.Printf("  %-18s %5s  %5s  %s\n", "────────────────", "─────", "─────", "──────────────────────────────")

	for _, r := range compatible {
		marker := " "
		if r.score == 6 {
			marker = "*"
		}
		fmt.Printf(" %s%-18s %d/6    %4dms  %s\n",
			marker, r.Host, r.score, r.LatencyMs, r.Tunnel.Details())
	}
	fmt.Println()
	fmt.Println("  * = fully compatible (6/6)")
	fmt.Println()

	// Print top resolvers as comma-separated for easy copy
	var top []string
	for _, r := range compatible {
		if r.score == 6 {
			top = append(top, r.Host)
		}
	}

	// E2E summary
	if e2eConfig != nil && len(e2eResults) > 0 {
		ep := atomic.LoadInt64(&e2ePassed)
		et := atomic.LoadInt64(&e2eTested)

		fmt.Println("  ── E2E Results ──────────────────────────────────")
		fmt.Println()
		fmt.Printf("  E2E: %d/%d passed\n", ep, et)
		fmt.Println()

		// Sort: passed first by latency, then failed
		e2eMu.Lock()
		sortedE2E := make([]E2EResult, len(e2eResults))
		copy(sortedE2E, e2eResults)
		e2eMu.Unlock()

		for i := 0; i < len(sortedE2E); i++ {
			for j := i + 1; j < len(sortedE2E); j++ {
				ri, rj := sortedE2E[i], sortedE2E[j]
				if (!ri.Success && rj.Success) ||
					(ri.Success == rj.Success && ri.TotalMs > rj.TotalMs) {
					sortedE2E[i], sortedE2E[j] = sortedE2E[j], sortedE2E[i]
				}
			}
		}

		fmt.Printf("  %-18s %7s  %7s  %7s  %s\n", "RESOLVER", "TUNNEL", "HTTP", "TOTAL", "STATUS")
		fmt.Printf("  %-18s %7s  %7s  %7s  %s\n", "────────────────", "───────", "───────", "───────", "──────")

		for _, r := range sortedE2E {
			if r.Success {
				fmt.Printf("  %-18s %5dms  %5dms  %5dms  PASS\n",
					r.Host, r.TunnelMs, r.HTTPMs, r.TotalMs)
			}
		}
		fmt.Println()

	}

	// Save results to files
	saveResultsPrompt(workingIPs, e2ePassedIPs)
}

func saveResultsPrompt(workingIPs []string, e2ePassedIPs []string) {
	if len(workingIPs) == 0 && len(e2ePassedIPs) == 0 {
		return
	}

	if reader == nil {
		reader = bufio.NewReader(os.Stdin)
	}

	fmt.Print("  Save results to files? (Y/n): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToLower(choice))
	if choice == "n" || choice == "no" {
		return
	}

	if len(workingIPs) > 0 {
		filename := "working.txt"
		content := strings.Join(workingIPs, "\n") + "\n"
		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			fmt.Printf("  Error saving: %v\n", err)
		} else {
			fmt.Printf("  Saved %d working IPs (6/6) to %s\n", len(workingIPs), filename)
		}
	}

	if len(e2ePassedIPs) > 0 {
		filename := "e2e_passed.txt"
		content := strings.Join(e2ePassedIPs, "\n") + "\n"
		if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
			fmt.Printf("  Error saving: %v\n", err)
		} else {
			fmt.Printf("  Saved %d E2E verified IPs to %s\n", len(e2ePassedIPs), filename)
		}
	}
	fmt.Println()
}
