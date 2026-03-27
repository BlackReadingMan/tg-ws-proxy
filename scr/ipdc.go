package main

import (
	"encoding/json"
	"os"
)

type ipInfo struct {
	Dc      int  `json:"dc"`
	IsMedia bool `json:"is_media"`
}

func loadIPToDC(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]ipInfo
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for ip, info := range m {
		ipToDC[ip] = struct {
			dc      int
			isMedia bool
		}{dc: info.Dc, isMedia: info.IsMedia}
	}
	return nil
}

// Функция для встроенной таблицы (если нужна)
func initBuiltinIPToDC() {
	ipToDC = map[string]struct {
		dc      int
		isMedia bool
	}{
		"149.154.175.50": {1, false}, "149.154.175.51": {1, false},
		"149.154.175.53": {1, false}, "149.154.175.54": {1, false},
		"149.154.175.52": {1, true},
		"149.154.167.35": {2, false},
		"149.154.167.41": {2, false}, "149.154.167.50": {2, false},
		"149.154.167.51": {2, false}, "149.154.167.220": {2, false},
		"95.161.76.100":   {2, false},
		"149.154.167.151": {2, true}, "149.154.167.222": {2, true},
		"149.154.167.223": {2, true},
		"149.154.162.123": {2, true},
		"149.154.175.100": {3, false}, "149.154.175.101": {3, false},
		"149.154.175.102": {3, true},
		"149.154.167.91":  {4, false}, "149.154.167.92": {4, false},
		"149.154.164.250": {4, true}, "149.154.167.255": {4, false},
		"149.154.166.120": {4, true},
		"149.154.166.121": {4, true}, "149.154.167.118": {4, true},
		"149.154.165.111": {4, true},
		"91.108.56.100":   {5, false}, "91.108.56.101": {5, false},
		"91.108.56.116": {5, false}, "91.108.56.126": {5, false},
		"149.154.171.5": {5, false},
		"91.108.56.102": {5, true}, "91.108.56.128": {5, true},
		"91.108.56.151":  {5, true},
		"91.105.192.100": {203, false},
	}
}
