package main

import (
	"sync"
	"time"
)

const (
	defaultPort    = 1080
	tcpNoDelay     = true
	recvBuf        = 256 * 1024
	sendBuf        = 256 * 1024
	wsPoolSize     = 4
	wsPoolMaxAge   = 120.0 // seconds
	dcFailCooldown = 30.0  // seconds
	wsFailTimeout  = 2.0   // seconds
)

var (
	// dcOpt maps DC number to target IP (for WebSocket)
	dcOpt map[int]string

	// ipToDC maps known Telegram IPs to their DC and media flag
	ipToDC = map[string]struct {
		dc      int
		isMedia bool
	}{
		"149.154.175.50": {1, false}, "149.154.175.51": {1, false},
		"149.154.175.53": {1, false}, "149.154.175.54": {1, false},
		"149.154.175.211": {1, false},
		"149.154.175.52":  {1, true},
		"149.154.167.35":  {2, false},
		"149.154.167.41":  {2, false}, "149.154.167.50": {2, false},
		"149.154.167.51": {2, false}, "149.154.167.220": {2, false},
		"95.161.76.100":   {2, false},
		"149.154.167.151": {2, true}, "149.154.167.222": {2, true},
		"149.154.167.223": {2, true}, "149.154.167.255": {4, false},
		"149.154.162.123": {2, true},
		"149.154.175.100": {3, false}, "149.154.175.101": {3, false},
		"149.154.175.102": {3, true},
		"149.154.167.91":  {4, false}, "149.154.167.92": {4, false},
		"149.154.164.250": {4, true}, "149.154.166.120": {4, true},
		"149.154.166.121": {4, true}, "149.154.167.118": {4, true},
		"149.154.165.111": {4, true},
		"91.108.56.100":   {5, false}, "91.108.56.101": {5, false},
		"91.108.56.116": {5, false}, "91.108.56.126": {5, false},
		"149.154.171.5":   {5, false},
		"149.154.171.255": {5, false},
		"91.108.56.102":   {5, true}, "91.108.56.128": {5, true},
		"91.108.56.151":  {5, true},
		"91.105.192.100": {203, false},
	}

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
