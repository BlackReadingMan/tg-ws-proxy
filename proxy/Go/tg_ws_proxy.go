package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	defaultPort    = 1080
	tcpNoDelay     = true
	recvBuf        = 65536
	sendBuf        = 65536
	wsPoolSize     = 4
	wsPoolMaxAge   = 120.0 // seconds
	dcFailCooldown = 60.0  // seconds
)

var tgRanges = []struct {
	start uint32
	end   uint32
}{
	{start: ipToUint32("185.76.151.0"), end: ipToUint32("185.76.151.255")},
	{start: ipToUint32("149.154.160.0"), end: ipToUint32("149.154.175.255")},
	{start: ipToUint32("91.105.192.0"), end: ipToUint32("91.105.193.255")},
	{start: ipToUint32("91.108.0.0"), end: ipToUint32("91.108.255.255")},
}

var ipToDC = map[string]struct {
	dc      int
	isMedia bool
}{
	"149.154.175.50": {1, false}, "149.154.175.51": {1, false},
	"149.154.175.53": {1, false}, "149.154.175.54": {1, false},
	"149.154.175.52": {1, true},
	"149.154.167.41": {2, false}, "149.154.167.50": {2, false},
	"149.154.167.51": {2, false}, "149.154.167.220": {2, false},
	"95.161.76.100":   {2, false},
	"149.154.167.151": {2, true}, "149.154.167.222": {2, true},
	"149.154.167.223": {2, true}, "149.154.162.123": {2, true},
	"149.154.175.100": {3, false}, "149.154.175.101": {3, false},
	"149.154.175.102": {3, true},
	"149.154.167.91":  {4, false}, "149.154.167.92": {4, false},
	"149.154.164.250": {4, true}, "149.154.166.120": {4, true},
	"149.154.166.121": {4, true}, "149.154.167.118": {4, true},
	"149.154.165.111": {4, true},
	"91.108.56.100":   {5, false}, "91.108.56.101": {5, false},
	"91.108.56.116": {5, false}, "91.108.56.126": {5, false},
	"149.154.171.5": {5, false},
	"91.108.56.102": {5, true}, "91.108.56.128": {5, true},
	"91.108.56.151": {5, true},
}

var dcOpt map[int]string // DC -> target IP

// wsBlacklist: (dc, isMedia) -> true if blacklisted
var wsBlacklist = struct {
	sync.RWMutex
	m map[[2]int]bool
}{m: make(map[[2]int]bool)}

// dcFailUntil: (dc, isMedia) -> unix timestamp until which WS is forbidden
var dcFailUntil = struct {
	sync.RWMutex
	m map[[2]int]time.Time
}{m: make(map[[2]int]time.Time)}

// stats
var stats = struct {
	connectionsTotal        int64
	connectionsWs           int64
	connectionsTcpFallback  int64
	connectionsHttpRejected int64
	connectionsPassthrough  int64
	wsErrors                int64
	bytesUp                 int64
	bytesDown               int64
	poolHits                int64
	poolMisses              int64
}{}

func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	return binary.BigEndian.Uint32(ip)
}

func isTelegramIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	n := binary.BigEndian.Uint32(ip.To4())
	for _, r := range tgRanges {
		if n >= r.start && n <= r.end {
			return true
		}
	}
	return false
}

func isHTTPTransport(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return strings.HasPrefix(string(data), "POST ") ||
		strings.HasPrefix(string(data), "GET ") ||
		strings.HasPrefix(string(data), "HEAD ") ||
		strings.HasPrefix(string(data), "OPTIONS ")
}

func dcFromInit(data []byte) (dc int, isMedia bool, ok bool) {
	if len(data) < 64 {
		return 0, false, false
	}
	key := data[8:40]
	iv := data[40:56]
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, false, false
	}
	stream := cipher.NewCTR(block, iv)
	keystream := make([]byte, 64)
	stream.XORKeyStream(keystream, make([]byte, 64)) // encrypt zeros
	plain := make([]byte, 8)
	for i := 0; i < 8; i++ {
		plain[i] = data[56+i] ^ keystream[56+i]
	}
	proto := binary.LittleEndian.Uint32(plain[0:4])
	dcRaw := int16(binary.LittleEndian.Uint16(plain[4:6]))
	if proto == 0xEFEFEFEF || proto == 0xEEEEEEEE || proto == 0xDDDDDDDD {
		dc := int(dcRaw)
		if dc < 0 {
			dc = -dc
			isMedia = true
		}
		if dc >= 1 && dc <= 5 {
			return dc, isMedia, true
		}
	}
	return 0, false, false
}

func patchInitDc(data []byte, dc int) []byte {
	if len(data) < 64 {
		return data
	}
	key := data[8:40]
	iv := data[40:56]
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)
	keystream := make([]byte, 64)
	stream.XORKeyStream(keystream, make([]byte, 64))
	newDc := make([]byte, 2)
	binary.LittleEndian.PutUint16(newDc, uint16(dc))
	patched := make([]byte, len(data))
	copy(patched, data)
	patched[60] = data[60] ^ keystream[60] ^ newDc[0]
	patched[61] = data[61] ^ keystream[61] ^ newDc[1]
	return patched
}

func wsDomains(dc int, isMedia bool) []string {
	if isMedia {
		return []string{fmt.Sprintf("kws%d-1.web.telegram.org", dc), fmt.Sprintf("kws%d.web.telegram.org", dc)}
	}
	return []string{fmt.Sprintf("kws%d.web.telegram.org", dc), fmt.Sprintf("kws%d-1.web.telegram.org", dc)}
}

type MsgSplitter struct {
	stream cipher.Stream
}

func NewMsgSplitter(initData []byte) (*MsgSplitter, error) {
	if len(initData) < 56 {
		return nil, fmt.Errorf("init data too short")
	}
	key := initData[8:40]
	iv := initData[40:56]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	// skip first 64 bytes of keystream (as in Python: decryptor.update(b'\x00'*64))
	dummy := make([]byte, 64)
	stream.XORKeyStream(dummy, dummy)
	return &MsgSplitter{stream: stream}, nil
}

func (s *MsgSplitter) Split(chunk []byte) [][]byte {
	// decrypt a copy to find boundaries
	plain := make([]byte, len(chunk))
	copy(plain, chunk)
	s.stream.XORKeyStream(plain, plain)

	boundaries := []int{}
	pos := 0
	for pos < len(plain) {
		first := plain[pos]
		if first == 0x7f {
			if pos+4 > len(plain) {
				break
			}
			msgLen := int(binary.LittleEndian.Uint32(plain[pos+1:pos+5])&0xFFFFFF) * 4
			pos += 4
			if msgLen == 0 || pos+msgLen > len(plain) {
				break
			}
			pos += msgLen
			boundaries = append(boundaries, pos)
		} else {
			msgLen := int(first) * 4
			pos += 1
			if msgLen == 0 || pos+msgLen > len(plain) {
				break
			}
			pos += msgLen
			boundaries = append(boundaries, pos)
		}
	}
	if len(boundaries) <= 1 {
		return [][]byte{chunk}
	}
	parts := make([][]byte, 0, len(boundaries))
	prev := 0
	for _, b := range boundaries {
		parts = append(parts, chunk[prev:b])
		prev = b
	}
	if prev < len(chunk) {
		parts = append(parts, chunk[prev:])
	}
	return parts
}

// -----------------------------------------------------------------------------
// WebSocket pool

type wsConn struct {
	conn    *websocket.Conn
	created time.Time
}

type wsPool struct {
	sync.Mutex
	idle      map[[2]int][]*wsConn // key: [dc, isMedia]
	refilling map[[2]int]bool
}

var pool = &wsPool{
	idle:      make(map[[2]int][]*wsConn),
	refilling: make(map[[2]int]bool),
}

func (p *wsPool) get(dc int, isMedia bool, targetIP string, domains []string) *websocket.Conn {
	key := [2]int{dc, boolToInt(isMedia)}
	p.Lock()
	defer p.Unlock()

	now := time.Now()
	bucket := p.idle[key]
	for len(bucket) > 0 {
		// pop front
		wc := bucket[0]
		bucket = bucket[1:]
		p.idle[key] = bucket

		age := now.Sub(wc.created).Seconds()
		if age > wsPoolMaxAge || wc.conn == nil {
			wc.conn.Close()
			continue
		}
		atomic.AddInt64(&stats.poolHits, 1)
		log.Printf("WS pool hit for DC%d%s (age=%.1fs, left=%d)", dc, mediaSuffix(isMedia), age, len(bucket))
		go p.refill(key, targetIP, domains) // async refill
		return wc.conn
	}
	atomic.AddInt64(&stats.poolMisses, 1)
	go p.refill(key, targetIP, domains)
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func mediaSuffix(isMedia bool) string {
	if isMedia {
		return "m"
	}
	return ""
}

func (p *wsPool) refill(key [2]int, targetIP string, domains []string) {
	p.Lock()
	if p.refilling[key] {
		p.Unlock()
		return
	}
	p.refilling[key] = true
	p.Unlock()

	defer func() {
		p.Lock()
		delete(p.refilling, key)
		p.Unlock()
	}()

	dc, isMediaBit := key[0], key[1]
	isMedia := isMediaBit == 1
	needed := wsPoolSize - len(p.idle[key])
	if needed <= 0 {
		return
	}

	var wg sync.WaitGroup
	wg.Add(needed)
	for i := 0; i < needed; i++ {
		go func() {
			defer wg.Done()
			conn, err := connectOne(targetIP, domains)
			if err != nil {
				return
			}
			p.Lock()
			p.idle[key] = append(p.idle[key], &wsConn{conn: conn, created: time.Now()})
			p.Unlock()
		}()
	}
	wg.Wait()
	log.Printf("WS pool refilled DC%d%s: %d ready", dc, mediaSuffix(isMedia), len(p.idle[key]))
}

func connectOne(targetIP string, domains []string) (*websocket.Conn, error) {
	for _, domain := range domains {
		dialer := &websocket.Dialer{
			TLSClientConfig: &tls.Config{
				ServerName: domain, // проверяем сертификат для этого домена
				// InsecureSkipVerify: false, // по умолчанию false, можно не указывать
			},
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Принудительно подключаемся к заданному IP, игнорируя DNS
				return (&net.Dialer{}).DialContext(ctx, network, targetIP+":443")
			},
			HandshakeTimeout: 8 * time.Second,
		}
		header := make(http.Header)
		header.Set("Origin", "https://web.telegram.org")
		header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
		header.Set("Sec-WebSocket-Protocol", "binary")

		url := "wss://" + domain + "/apiws"
		conn, resp, err := dialer.Dial(url, header)
		if err != nil {
			if resp != nil && (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 303 || resp.StatusCode == 307 || resp.StatusCode == 308) {
				continue
			}
			return nil, err
		}
		conn.SetPingHandler(func(appData string) error {
			return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		})
		return conn, nil
	}
	return nil, fmt.Errorf("all domains failed")
}

// -----------------------------------------------------------------------------
// SOCKS5 helpers

func socks5Reply(status byte) []byte {
	return []byte{0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

// -----------------------------------------------------------------------------
// TCP bridge functions

func pipe(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		srcConn, ok := src.(net.Conn)
		if ok {
			srcConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
		n, err := src.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		if n == 0 {
			return nil
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return err
		}
	}
}

func bridgeTCP(ctx context.Context, client, remote net.Conn, label string, dc int, isMedia bool, dstIP string, port int) {
	defer remote.Close()
	defer client.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errChan := make(chan error, 2)
	go func() {
		errChan <- pipe(ctx, remote, client)
		cancel()
	}()
	go func() {
		errChan <- pipe(ctx, client, remote)
		cancel()
	}()

	<-errChan
	<-errChan
	log.Printf("[%s] DC%d%s (%s:%d) TCP fallback closed", label, dc, mediaSuffix(isMedia), dstIP, port)
}

func bridgeWS(ctx context.Context, client net.Conn, ws *websocket.Conn, label string, dc int, isMedia bool, dstIP string, port int, splitter *MsgSplitter) {
	defer ws.Close()
	defer client.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errChan := make(chan error, 2)

	// client -> ws
	go func() {
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				errChan <- nil
				return
			default:
			}
			client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := client.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				errChan <- err
				return
			}
			if n == 0 {
				errChan <- nil
				return
			}
			data := buf[:n]
			atomic.AddInt64(&stats.bytesUp, int64(n))
			if splitter != nil {
				parts := splitter.Split(data)
				for _, p := range parts {
					if err := ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
						errChan <- err
						return
					}
				}
			} else {
				if err := ws.WriteMessage(websocket.BinaryMessage, data); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	// ws -> client
	go func() {
		for {
			select {
			case <-ctx.Done():
				errChan <- nil
				return
			default:
			}
			_, msg, err := ws.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			atomic.AddInt64(&stats.bytesDown, int64(len(msg)))
			if _, err := client.Write(msg); err != nil {
				errChan <- err
				return
			}
		}
	}()

	<-errChan
	cancel()
	<-errChan
	log.Printf("[%s] DC%d%s (%s:%d) WS session closed", label, dc, mediaSuffix(isMedia), dstIP, port)
}

func tcpFallback(ctx context.Context, client net.Conn, dstIP string, port int, init []byte, label string, dc int, isMedia bool) bool {
	remote, err := net.DialTimeout("tcp", net.JoinHostPort(dstIP, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		log.Printf("[%s] TCP fallback connect to %s:%d failed: %v", label, dstIP, port, err)
		return false
	}
	if _, err := remote.Write(init); err != nil {
		remote.Close()
		return false
	}
	atomic.AddInt64(&stats.connectionsTcpFallback, 1)
	go bridgeTCP(ctx, client, remote, label, dc, isMedia, dstIP, port)
	return true
}

// -----------------------------------------------------------------------------
// Client handler

func handleClient(conn net.Conn) {
	defer conn.Close()
	label := conn.RemoteAddr().String()
	atomic.AddInt64(&stats.connectionsTotal, 1)

	// set socket options
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(tcpNoDelay)
		tcpConn.SetReadBuffer(recvBuf)
		tcpConn.SetWriteBuffer(sendBuf)
	}

	// SOCKS5 greeting
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	if buf[0] != 5 {
		log.Printf("[%s] not SOCKS5 (ver=%d)", label, buf[0])
		return
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, make([]byte, nmethods)); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00}) // no auth

	// SOCKS5 request
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	if req[1] != 1 { // CMD CONNECT
		conn.Write(socks5Reply(0x07))
		return
	}
	atyp := req[3]
	var dstAddr string
	switch atyp {
	case 1: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		dstAddr = net.IP(ip).String()
	case 3: // domain
		lenb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenb); err != nil {
			return
		}
		domain := make([]byte, lenb[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		dstAddr = string(domain)
	case 4: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		dstAddr = net.IP(ip).String()
	default:
		conn.Write(socks5Reply(0x08))
		return
	}

	portb := make([]byte, 2)
	if _, err := io.ReadFull(conn, portb); err != nil {
		return
	}
	dstPort := int(binary.BigEndian.Uint16(portb))

	// check IPv6
	if strings.Contains(dstAddr, ":") {
		log.Printf("[%s] IPv6 address detected: %s:%d — not supported", label, dstAddr, dstPort)
		conn.Write(socks5Reply(0x05))
		return
	}

	// Non-Telegram IP -> direct passthrough
	if !isTelegramIP(dstAddr) {
		atomic.AddInt64(&stats.connectionsPassthrough, 1)
		log.Printf("[%s] passthrough -> %s:%d", label, dstAddr, dstPort)
		remote, err := net.DialTimeout("tcp", net.JoinHostPort(dstAddr, strconv.Itoa(dstPort)), 10*time.Second)
		if err != nil {
			log.Printf("[%s] passthrough failed to %s: %v", label, dstAddr, err)
			conn.Write(socks5Reply(0x05))
			return
		}
		conn.Write(socks5Reply(0x00))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errChan := make(chan error, 2)
		go func() { errChan <- pipe(ctx, remote, conn) }()
		go func() { errChan <- pipe(ctx, conn, remote) }()
		<-errChan
		cancel()
		<-errChan
		return
	}

	// Telegram: accept SOCKS, read 64-byte init
	conn.Write(socks5Reply(0x00))

	init := make([]byte, 64)
	if _, err := io.ReadFull(conn, init); err != nil {
		log.Printf("[%s] client disconnected before init", label)
		return
	}

	// HTTP transport -> reject
	if isHTTPTransport(init) {
		atomic.AddInt64(&stats.connectionsHttpRejected, 1)
		log.Printf("[%s] HTTP transport to %s:%d (rejected)", label, dstAddr, dstPort)
		return
	}

	// Extract DC
	dc, isMedia, ok := dcFromInit(init)
	patched := false
	if !ok {
		if info, exists := ipToDC[dstAddr]; exists {
			dc, isMedia = info.dc, info.isMedia
			if targetIP, ok := dcOpt[dc]; ok && targetIP != "" {
				init = patchInitDc(init, dc)
				patched = true
			}
		}
	}
	if dc == 0 || dcOpt[dc] == "" {
		log.Printf("[%s] unknown DC for %s:%d -> TCP passthrough", label, dstAddr, dstPort)
		tcpFallback(context.Background(), conn, dstAddr, dstPort, init, label, 0, false)
		return
	}

	key := [2]int{dc, boolToInt(isMedia)}
	now := time.Now()

	// Blacklist check
	wsBlacklist.RLock()
	blacklisted := wsBlacklist.m[key]
	wsBlacklist.RUnlock()
	if blacklisted {
		log.Printf("[%s] DC%d%s WS blacklisted -> TCP %s:%d", label, dc, mediaSuffix(isMedia), dstAddr, dstPort)
		if tcpFallback(context.Background(), conn, dstAddr, dstPort, init, label, dc, isMedia) {
			log.Printf("[%s] DC%d%s TCP fallback closed", label, dc, mediaSuffix(isMedia))
		}
		return
	}

	// Cooldown check
	dcFailUntil.RLock()
	failUntil, exists := dcFailUntil.m[key]
	dcFailUntil.RUnlock()
	if exists && now.Before(failUntil) {
		remaining := failUntil.Sub(now).Seconds()
		log.Printf("[%s] DC%d%s WS cooldown (%.0fs) -> TCP", label, dc, mediaSuffix(isMedia), remaining)
		if tcpFallback(context.Background(), conn, dstAddr, dstPort, init, label, dc, isMedia) {
			log.Printf("[%s] DC%d%s TCP fallback closed", label, dc, mediaSuffix(isMedia))
		}
		return
	}

	// Try WebSocket
	targetIP := dcOpt[dc]
	domains := wsDomains(dc, isMedia)
	wsConn := pool.get(dc, isMedia, targetIP, domains)
	if wsConn == nil {
		// No pool hit, try to connect directly
		var err error
		wsConn, err = connectOne(targetIP, domains)
		if err != nil {
			atomic.AddInt64(&stats.wsErrors, 1)
			dcFailUntil.Lock()
			dcFailUntil.m[key] = now.Add(dcFailCooldown * time.Second)
			dcFailUntil.Unlock()
			log.Printf("[%s] DC%d%s -> TCP fallback to %s:%d (WS connect failed)", label, dc, mediaSuffix(isMedia), dstAddr, dstPort)
			if tcpFallback(context.Background(), conn, dstAddr, dstPort, init, label, dc, isMedia) {
				log.Printf("[%s] DC%d%s TCP fallback closed", label, dc, mediaSuffix(isMedia))
			}
			return
		}
		// success, wsConn assigned
	}

	// WS success, clear cooldown
	dcFailUntil.Lock()
	delete(dcFailUntil.m, key)
	dcFailUntil.Unlock()
	atomic.AddInt64(&stats.connectionsWs, 1)

	var splitter *MsgSplitter
	if patched {
		splitter, _ = NewMsgSplitter(init)
	}
	// send init
	if err := wsConn.WriteMessage(websocket.BinaryMessage, init); err != nil {
		wsConn.Close()
		return
	}
	// bridge
	bridgeWS(context.Background(), conn, wsConn, label, dc, isMedia, dstAddr, dstPort, splitter)
}

// -----------------------------------------------------------------------------
// Main

func main() {
	var (
		port    = flag.Int("port", defaultPort, "listen port")
		host    = flag.String("host", "127.0.0.1", "listen host")
		dcIps   = flag.String("dc-ip", "", "comma-separated DC:IP pairs, e.g. 1:149.154.175.50,2:149.154.167.220")
		verbose = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

	if *dcIps == "" {
		// default
		*dcIps = "2:149.154.167.220,4:149.154.167.220"
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
	}
	log.Printf("Log level: %s", logLevel)
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// start server
	ln, err := net.Listen("tcp", net.JoinHostPort(*host, strconv.Itoa(*port)))
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("=" + strings.Repeat("=", 60))
	log.Printf("  Telegram WS Bridge Proxy")
	log.Printf("  Listening on   %s:%d", *host, *port)
	log.Printf("  Target DC IPs:")
	for dc, ip := range dcOpt {
		log.Printf("    DC%d: %s", dc, ip)
	}
	log.Printf("=" + strings.Repeat("=", 60))
	log.Printf("  Configure Telegram Desktop:")
	log.Printf("    SOCKS5 proxy -> %s:%d  (no user/pass)", *host, *port)
	log.Printf("=" + strings.Repeat("=", 60))

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

func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}
