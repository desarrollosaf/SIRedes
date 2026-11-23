package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SysInfo struct {
	Hostname  string    `json:"hostname"`
	Version   string    `json:"version"`
	Uptime    float64   `json:"uptime"` // segundos
	CPU       float64   `json:"cpu"`    // %
	MemTotal  uint64    `json:"memTotal"`
	MemUsed   uint64    `json:"memUsed"`
	DiskTotal uint64    `json:"diskTotal"`
	DiskUsed  uint64    `json:"diskUsed"`
	TempC     float64   `json:"tempC"`
	Load      string    `json:"load"`
	RxBps     float64   `json:"rxBps"`
	TxBps     float64   `json:"txBps"`
	Iface     string    `json:"iface"`
	IP        string    `json:"ip"`
	Subnet    string    `json:"subnet"`
	Scanning  bool      `json:"scanning"`
	LastScan  time.Time `json:"lastScan"`
	RoundSecs float64   `json:"roundSecs"` // cuánto tardó la última ronda de revisión
	RoundN    int       `json:"roundN"`    // equipos revisados en esa ronda
	EverySecs float64   `json:"everySecs"` // cada cuánto se revisa`
	CPUHist   []float64 `json:"cpuHist"`
	RxHist    []float64 `json:"rxHist"`
	TxHist    []float64 `json:"txHist"`
}

var (
	sysMu  sync.RWMutex
	sysNow SysInfo
)

func currentSys() SysInfo {
	sysMu.RLock()
	defer sysMu.RUnlock()
	s := sysNow
	s.CPUHist = append([]float64(nil), sysNow.CPUHist...)
	s.RxHist = append([]float64(nil), sysNow.RxHist...)
	s.TxHist = append([]float64(nil), sysNow.TxHist...)
	return s
}

func push(h []float64, v float64) []float64 {
	h = append(h, v)
	if len(h) > 60 {
		h = h[len(h)-60:]
	}
	return h
}

func sysCollector() {
	var prevIdle, prevTotal uint64
	var prevRx, prevTx uint64
	prevT := time.Now()
	for {
		s := SysInfo{}
		s.Hostname, _ = os.Hostname()

		// CPU
		idle, total := readCPU()
		cpu := 0.0
		if prevTotal > 0 && total > prevTotal {
			cpu = 100 * (1 - float64(idle-prevIdle)/float64(total-prevTotal))
		}
		prevIdle, prevTotal = idle, total
		s.CPU = cpu

		// memoria
		mt, ma := readMem()
		s.MemTotal, s.MemUsed = mt, mt-ma

		// disco
		s.DiskTotal, s.DiskUsed = discoUso("/")

		// temperatura (Raspberry Pi)
		if b, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
			v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
			s.TempC = v / 1000
		}
		if b, err := os.ReadFile("/proc/uptime"); err == nil {
			f := strings.Fields(string(b))
			if len(f) > 0 {
				s.Uptime, _ = strconv.ParseFloat(f[0], 64)
			}
		}
		if b, err := os.ReadFile("/proc/loadavg"); err == nil {
			f := strings.Fields(string(b))
			if len(f) >= 3 {
				s.Load = f[0] + " " + f[1] + " " + f[2]
			}
		}

		// tráfico de la interfaz principal
		if li := localIface(); li != nil {
			s.Iface, s.IP = li.name, li.ip.String()
			rx, tx := readNetDev(li.name)
			now := time.Now()
			dt := now.Sub(prevT).Seconds()
			if prevRx > 0 && dt > 0 && rx >= prevRx && tx >= prevTx {
				s.RxBps = float64(rx-prevRx) / dt
				s.TxBps = float64(tx-prevTx) / dt
			}
			prevRx, prevTx, prevT = rx, tx, now
		}

		sysMu.Lock()
		s.CPUHist = push(sysNow.CPUHist, s.CPU)
		s.RxHist = push(sysNow.RxHist, s.RxBps)
		s.TxHist = push(sysNow.TxHist, s.TxBps)
		sysNow = s
		sysMu.Unlock()

		time.Sleep(5 * time.Second)
	}
}

func readCPU() (idle, total uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	f := strings.Fields(line)
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	return
}

func readMem() (total, avail uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(p[1], 10, 64)
		switch p[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	return
}

func readNetDev(iface string) (rx, tx uint64) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, ":")
		if i < 0 || strings.TrimSpace(line[:i]) != iface {
			continue
		}
		p := strings.Fields(line[i+1:])
		if len(p) >= 9 {
			rx, _ = strconv.ParseUint(p[0], 10, 64)
			tx, _ = strconv.ParseUint(p[8], 10, 64)
		}
	}
	return
}
