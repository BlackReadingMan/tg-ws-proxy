package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

func main() {
	var (
		port       = flag.Int("port", defaultPort, "listen port")
		host       = flag.String("host", "127.0.0.1", "listen host")
		dcIps      = flag.String("dc-ip", "", "comma-separated DC:IP pairs, e.g. 2:149.154.167.220,4:149.154.167.220")
		bufKB      = flag.Int("buf-kb", 256, "socket send/recv buffer size in KB")
		poolSize   = flag.Int("pool-size", 4, "WS connection pool size per DC")
		verbose    = flag.Bool("v", false, "verbose logging")
		ipToDCFile = flag.String("ip-dc-file", "ip_to_dc.json", "path to JSON file with IP->DC mapping (optional)")
	)
	flag.Parse()

	if *dcIps == "" {
		*dcIps = "2:149.154.167.220,4:149.154.167.220,203:149.154.167.220"
	}

	// parse dc-ip
	dcOpt = make(map[int]string)
	pairs := strings.Split(*dcIps, ",")
	for _, p := range pairs {
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			log.Fatalf("Invalid --dc-ip format %q, expected DC:IP", p)
		}
		dc, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Fatalf("Invalid DC number %q", parts[0])
		}
		ip := net.ParseIP(parts[1])
		if ip == nil || ip.To4() == nil {
			log.Fatalf("Invalid IPv4 address %q", parts[1])
		}
		dcOpt[dc] = parts[1]
	}

	logLevel := "INFO"
	if *verbose {
		logLevel = "DEBUG"
		debug = true
	}
	log.Printf("Log level: %s", logLevel)
	log.SetFlags(log.Ltime)

	recvBuf = *bufKB * 1024
	sendBuf = recvBuf
	wsPoolSize = *poolSize

	if err := loadIPToDC(*ipToDCFile); err != nil {
		log.Printf("Failed to load IP->DC mapping: %v", err)
		initBuiltinIPToDC()
	}
	log.Printf("Loaded IP->DC mapping from %s (%d entries)", *ipToDCFile, len(ipToDC))

	// start server
	ln, err := net.Listen("tcp", net.JoinHostPort(*host, strconv.Itoa(*port)))
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("%s", "="+strings.Repeat("=", 60))
	log.Printf("  Telegram WS Bridge Proxy")
	log.Printf("  Listening on   %s:%d", *host, *port)
	log.Printf("  Target DC IPs:")
	for dc, ip := range dcOpt {
		log.Printf("    DC%d: %s", dc, ip)
	}
	log.Printf("%s", "="+strings.Repeat("=", 60))
	log.Printf("  Configure Telegram Desktop:")
	log.Printf("    SOCKS5 proxy -> %s:%d  (no user/pass)", *host, *port)
	log.Printf("%s", "="+strings.Repeat("=", 60))

	// warm up pool
	for dc, ip := range dcOpt {
		for _, isMedia := range []bool{false, true} {
			key := [2]int{dc, boolToInt(isMedia)}
			domains := wsDomains(dc, isMedia)
			go pool.refill(key, ip, domains)
		}
	}
	log.Printf("WS pool warmup started for %d DC(s)", len(dcOpt))

	// stats logger
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			wsBlacklist.RLock()
			bl := make([]string, 0, len(wsBlacklist.m))
			for k := range wsBlacklist.m {
				bl = append(bl, fmt.Sprintf("DC%d%s", k[0], mediaSuffix(k[1] == 1)))
			}
			wsBlacklist.RUnlock()
			if len(bl) == 0 {
				bl = []string{"none"}
			}
			log.Printf("stats: total=%d ws=%d tcp_fb=%d http_skip=%d pass=%d err=%d pool=%d/%d up=%s down=%s | ws_bl: %s",
				atomic.LoadInt64(&stats.connectionsTotal),
				atomic.LoadInt64(&stats.connectionsWs),
				atomic.LoadInt64(&stats.connectionsTcpFallback),
				atomic.LoadInt64(&stats.connectionsHttpRejected),
				atomic.LoadInt64(&stats.connectionsPassthrough),
				atomic.LoadInt64(&stats.wsErrors),
				atomic.LoadInt64(&stats.poolHits),
				atomic.LoadInt64(&stats.poolHits)+atomic.LoadInt64(&stats.poolMisses),
				humanBytes(atomic.LoadInt64(&stats.bytesUp)),
				humanBytes(atomic.LoadInt64(&stats.bytesDown)),
				strings.Join(bl, ", "))
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleClient(conn)
	}
}
