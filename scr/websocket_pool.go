package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

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
		go p.refill(key, targetIP, domains)
		return wc.conn
	}
	atomic.AddInt64(&stats.poolMisses, 1)
	go p.refill(key, targetIP, domains)
	return nil
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
			conn, err := connectOne(targetIP, domains, 8*time.Second)
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

func connectOne(targetIP string, domains []string, timeout time.Duration) (*websocket.Conn, error) {
	for _, domain := range domains {
		dialer := &websocket.Dialer{
			TLSClientConfig: &tls.Config{
				ServerName: domain,
			},
			NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, targetIP+":443")
			},
			HandshakeTimeout: timeout,
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
