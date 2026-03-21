package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

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
		if (dc >= 1 && dc <= 5) || dc == 203 {
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
	if override, ok := dcOverrides[dc]; ok {
		dc = override
	}
	if isMedia {
		return []string{fmt.Sprintf("kws%d-1.web.telegram.org", dc), fmt.Sprintf("kws%d.web.telegram.org", dc)}
	}
	return []string{fmt.Sprintf("kws%d.web.telegram.org", dc), fmt.Sprintf("kws%d-1.web.telegram.org", dc)}
}

func mediaSuffix(isMedia bool) string {
	if isMedia {
		return "m"
	}
	return ""
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
