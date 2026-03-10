package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var defaultDoHResolvers = []string{
	"https://dns.google/dns-query",
	"https://cloudflare-dns.com/dns-query",
	"https://doh.opendns.com/dns-query",
	"https://doh.cleanbrowsing.org/doh/security-filter",
	"https://dns.nextdns.io/dns-query",
	"https://doh.mullvad.net/dns-query",
	"https://dns0.eu/dns-query",
	"https://ordns.he.net/dns-query",
	"https://dns.quad9.net/dns-query",
	"https://dns.adguard-dns.com/dns-query",
}

type arrayFlags []string

func (a *arrayFlags) String() string { return strings.Join(*a, ", ") }
func (a *arrayFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func main() {
	var (
		listen       string
		resolvers    arrayFlags
		resolverFile string
		doh          bool
		noAutoSelect bool
		mode         string
		tcp          bool
		cover        bool
		coverMin     float64
		coverMax     float64
		healthCheck  bool
		stats        bool
		scan         bool
		scanDomain   string
		logLevel     string
		cacheEnabled bool
		cacheSize    int
	)

	flag.StringVar(&listen, "listen", "0.0.0.0:53", "Listen address:port")
	flag.StringVar(&listen, "l", "0.0.0.0:53", "Listen address:port (shorthand)")
	flag.Var(&resolvers, "resolver", "Upstream resolver (can repeat)")
	flag.Var(&resolvers, "r", "Upstream resolver (shorthand, can repeat)")
	flag.StringVar(&resolverFile, "resolvers-file", "", "File with resolver list")
	flag.StringVar(&resolverFile, "f", "", "File with resolver list (shorthand)")
	flag.BoolVar(&doh, "doh", false, "Use DoH (DNS over HTTPS) for upstream")
	flag.BoolVar(&noAutoSelect, "no-auto-select", false, "Skip startup probe")
	flag.StringVar(&mode, "mode", "round-robin", "Distribution mode: round-robin or random")
	flag.StringVar(&mode, "m", "round-robin", "Distribution mode (shorthand)")
	flag.BoolVar(&tcp, "tcp", false, "Also listen for TCP DNS queries")
	flag.BoolVar(&cover, "cover", false, "Generate cover traffic")
	flag.Float64Var(&coverMin, "cover-min", 5.0, "Min cover traffic interval (seconds)")
	flag.Float64Var(&coverMax, "cover-max", 15.0, "Max cover traffic interval (seconds)")
	flag.BoolVar(&healthCheck, "health-check", false, "Enable periodic health checks")
	flag.BoolVar(&stats, "stats", false, "Log query statistics periodically")
	flag.BoolVar(&scan, "scan", false, "Scan resolvers for tunnel compatibility")
	flag.StringVar(&scanDomain, "scan-domain", "", "Tunnel domain for scanning")
	flag.StringVar(&logLevel, "log-level", "INFO", "Log level: DEBUG, INFO, WARNING, ERROR")
	flag.BoolVar(&cacheEnabled, "cache", false, "Enable DNS response cache")
	flag.IntVar(&cacheSize, "cache-size", 10000, "Max cache entries")

	flag.Parse()

	// Configure logging
	var level slog.Level
	switch strings.ToUpper(logLevel) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	// Parse resolvers
	parsed := parseResolvers(resolverFile, resolvers, doh)

	// Scan mode
	if scan {
		if scanDomain == "" {
			fmt.Fprintln(os.Stderr, "Error: --scan requires --scan-domain (e.g. --scan-domain t.example.com)")
			os.Exit(1)
		}
		if len(parsed) == 0 {
			if doh {
				for _, u := range defaultDoHResolvers {
					parsed = append(parsed, Resolver{URL: u})
				}
			} else {
				fmt.Fprintln(os.Stderr, "Error: no resolvers specified. Use -r or -f.")
				os.Exit(1)
			}
		}
		runScan(parsed, scanDomain, doh, 10)
		os.Exit(0)
	}

	// Proxy mode
	if len(parsed) == 0 {
		if doh {
			slog.Info("No resolvers specified, using default DoH resolvers")
			for _, u := range defaultDoHResolvers {
				parsed = append(parsed, Resolver{URL: u})
			}
		} else {
			fmt.Fprintln(os.Stderr, "Error: no resolvers configured. Use -r or -f to specify resolvers.")
			os.Exit(1)
		}
	}

	pool := NewResolverPool(parsed, mode, doh)

	modeStr := "UDP"
	if doh {
		modeStr = "DoH (HTTPS)"
	}
	slog.Info("DNS Multiplexer starting", "upstream", modeStr)
	slog.Info("Distribution mode", "mode", mode)
	slog.Info("Loaded resolvers", "count", len(pool.resolvers))

	// Startup probe
	if !noAutoSelect {
		working := ProbeResolvers(pool)
		pool = NewResolverPool(working, mode, doh)
	} else {
		for _, r := range pool.resolvers {
			slog.Info("Resolver", "addr", r)
		}
	}

	// Cache
	var cache *DNSCache
	if cacheEnabled {
		cache = NewDNSCache(cacheSize)
		slog.Info("DNS cache enabled", "max_entries", cacheSize)
	}

	// UDP proxy (always)
	udp := NewUDPProxy(listen, pool, cache)
	go func() {
		if err := udp.Start(); err != nil {
			slog.Error("UDP proxy failed", "err", err)
			os.Exit(1)
		}
	}()

	// TCP proxy (optional)
	var tcpProxy *TCPProxy
	if tcp {
		tcpProxy = NewTCPProxy(listen, pool, cache)
		go func() {
			if err := tcpProxy.Start(); err != nil {
				slog.Error("TCP proxy failed", "err", err)
			}
		}()
	}

	// Cover traffic (optional)
	var coverTraffic *CoverTraffic
	if cover {
		coverTraffic = NewCoverTraffic(pool, coverMin, coverMax)
		coverTraffic.Start()
	}

	// Health check loop
	if healthCheck {
		go func() {
			for {
				time.Sleep(HealthCheckInterval)
				pool.HealthCheck()
				slog.Info("Health check", "healthy", pool.HealthyCount(), "total", len(pool.resolvers))
			}
		}()
	}

	// Stats loop
	if stats {
		go func() {
			for {
				time.Sleep(StatsInterval)
				slog.Info("Stats", "queries", udp.QueryCount())
				fmt.Fprint(os.Stderr, pool.StatsString())
			}
		}()
	}

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("Shutting down...")
	udp.Stop()
	if tcpProxy != nil {
		tcpProxy.Stop()
	}
	if coverTraffic != nil {
		coverTraffic.Stop()
	}
}

func parseResolvers(file string, rawResolvers []string, doh bool) []Resolver {
	var resolvers []Resolver

	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			slog.Error("Failed to open resolvers file", "file", file, "err", err)
		} else {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if r, ok := parseOneResolver(line, doh); ok {
					resolvers = append(resolvers, r)
				}
			}
		}
	}

	for _, raw := range rawResolvers {
		if r, ok := parseOneResolver(raw, doh); ok {
			resolvers = append(resolvers, r)
		}
	}

	return resolvers
}

func parseOneResolver(value string, doh bool) (Resolver, bool) {
	value = strings.TrimSpace(value)
	if doh {
		if strings.HasPrefix(value, "https://") {
			return Resolver{URL: value}, true
		}
		return Resolver{URL: fmt.Sprintf("https://%s/dns-query", value)}, true
	}
	// UDP mode: IP or IP:PORT
	if strings.Contains(value, ":") {
		return Resolver{Addr: value}, true
	}
	return Resolver{Addr: value + ":53"}, true
}
