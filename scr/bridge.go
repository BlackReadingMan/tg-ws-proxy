package main

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

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
