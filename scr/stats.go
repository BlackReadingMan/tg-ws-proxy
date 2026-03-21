package main

import (
	"fmt"
)

// statistics counters (atomic)
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
