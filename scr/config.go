package main

import (
	"sync"
	"time"
)

const (
	defaultPort    = 1080
	tcpNoDelay     = true
	wsPoolMaxAge   = 120.0 // seconds
	dcFailCooldown = 30.0  // seconds
	wsFailTimeout  = 2.0   // seconds
)

var (
	recvBuf    = 256 * 1024
	sendBuf    = 256 * 1024
	wsPoolSize = 4
	debug      = false
)

var (
	// dcOpt maps DC number to target IP (for WebSocket)
	dcOpt map[int]string

	// ipToDC maps known Telegram IPs to their DC and media flag
	ipToDC = make(map[string]struct {
		dc      int
		isMedia bool
	})

	// dcOverrides maps non‑standard DC numbers (e.g., 203) to actual DCs
	dcOverrides = map[int]int{
		203: 2,
	}
)

// tgRanges lists IPv4 subnets used by Telegram
var tgRanges = []struct {
	start uint32
	end   uint32
}{
	{start: ipToUint32("185.76.151.0"), end: ipToUint32("185.76.151.255")},
	{start: ipToUint32("149.154.160.0"), end: ipToUint32("149.154.175.255")},
	{start: ipToUint32("91.105.192.0"), end: ipToUint32("91.105.193.255")},
	{start: ipToUint32("91.108.0.0"), end: ipToUint32("91.108.255.255")},
}

// wsBlacklist stores DCs where WebSocket is known to fail
var wsBlacklist = struct {
	sync.RWMutex
	m map[[2]int]bool
}{m: make(map[[2]int]bool)}

// dcFailUntil stores cooldown timestamps for each DC
var dcFailUntil = struct {
	sync.RWMutex
	m map[[2]int]time.Time
}{m: make(map[[2]int]time.Time)}
