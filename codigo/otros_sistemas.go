//go:build !linux

// otros_sistemas.go — reemplazos de las partes de Linux para poder correr el
// programa en la PC de desarrollo (Windows) y revisar las pantallas. En la Pi
// (Linux) este archivo no se compila. Aquí no hay ARP crudo ni detección de red.
package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

var arpDisabled = func() *atomic.Bool { var b atomic.Bool; b.Store(true); return &b }()

func arpPing(ip, mac string, timeout time.Duration) (float64, bool) { return 0, false }
func arpProbe(ip string) bool                                       { return false }
func arpSweep(prefix string)                                        {}
func (m *Monitor) ARPListen()                                       {}
func discoUso(ruta string) (total, usado uint64)                    { return 0, 0 }

func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error { return nil }

func detectNetwork(ifname, current, curGW string, secs int) int {
	fmt.Fprintln(os.Stderr, "detectar red: solo en Linux")
	return 1
}
