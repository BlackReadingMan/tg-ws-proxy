package main

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

func socks5Reply(status byte) []byte {
	return []byte{0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
}

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
	timeout := 10 * time.Second
	dcFailUntil.RLock()
	failUntil, exists := dcFailUntil.m[key]
	dcFailUntil.RUnlock()
	if exists && now.Before(failUntil) {
		timeout = wsFailTimeout * time.Second
		log.Printf("[%s] DC%d%s WS cooldown active, using timeout %.0fs", label, dc, mediaSuffix(isMedia), timeout.Seconds())
	}

	// Try WebSocket
	targetIP := dcOpt[dc]
	domains := wsDomains(dc, isMedia)
	wsConn := pool.get(dc, isMedia, targetIP, domains)
	if wsConn == nil {
		// No pool hit, try to connect directly
		var err error
		wsConn, err = connectOne(targetIP, domains, timeout)
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
