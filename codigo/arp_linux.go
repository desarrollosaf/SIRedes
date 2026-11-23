//go:build linux

package main

// arpPing pregunta directamente por ARP "¿quién tiene esta IP?" y mide cuánto
// tarda la respuesta. Sirve para equipos cuyo firewall bloquea el ping
// (Windows, impresoras): ningún equipo puede dejar de contestar ARP y seguir
// en la red. Necesita CAP_NET_RAW (el servicio la recibe en install.sh).

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var arpDisabled atomic.Bool // se activa si no hay permisos para ARP crudo

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func arpPing(ip, mac string, timeout time.Duration) (float64, bool) {
	if arpDisabled.Load() {
		return -1, false
	}
	self := localIface()
	dst := net.ParseIP(ip).To4()
	// funciona también con equipos de otros segmentos conectados al mismo switch
	if self == nil || dst == nil {
		return -1, false
	}
	ifi, err := net.InterfaceByName(self.name)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		return -1, false
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		arpDisabled.Store(true) // sin permisos: se usa el método anterior
		return -1, false
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ARP), Ifindex: ifi.Index}); err != nil {
		return -1, false
	}

	// solicitud ARP (28 bytes)
	pkt := make([]byte, 28)
	pkt[0], pkt[1] = 0, 1 // Ethernet
	pkt[2], pkt[3] = 8, 0 // IPv4
	pkt[4], pkt[5] = 6, 4 // tamaños
	pkt[6], pkt[7] = 0, 1 // solicitud
	copy(pkt[8:14], ifi.HardwareAddr)
	if self.net.Contains(dst) {
		copy(pkt[14:18], self.ip.To4())
	}
	// Si es de OTRO segmento, va como "ARP probe" (IP de origen 0.0.0.0, la consulta
	// estándar para ver si una IP está ocupada): el dueño contesta aunque la Pi no
	// esté en su segmento. Con nuestra IP, muchos routers la ignoran.
	copy(pkt[24:28], dst)

	to := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ARP), Ifindex: ifi.Index, Halen: 6}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		hw = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	copy(to.Addr[:], hw)

	tv := syscall.NsecToTimeval(int64(200 * time.Millisecond))
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	start := time.Now()
	if err := syscall.Sendto(fd, pkt, 0, to); err != nil {
		return -1, false
	}
	buf := make([]byte, 128)
	deadline := start.Add(timeout)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 28 {
			continue
		}
		if buf[6] == 0 && buf[7] == 2 && net.IP(buf[14:18]).Equal(dst) { // respuesta de esa IP
			return float64(time.Since(start).Microseconds()) / 1000, true
		}
	}
	return -1, false
}

// bindToDevice amarra un socket a una interfaz (SO_BINDTODEVICE, con CAP_NET_RAW).
func bindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		})
		return serr
	}
}

func wiredIface() (*ifaceInfo, *net.Interface) {
	self := localIface()
	if self == nil || !(strings.HasPrefix(self.name, "eth") || strings.HasPrefix(self.name, "en")) {
		return nil, nil
	}
	ifi, err := net.InterfaceByName(self.name)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		return nil, nil
	}
	return self, ifi
}

func arpSocket(ifi *net.Interface) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		return -1, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ARP), Ifindex: ifi.Index}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

// ARPListen escucha todos los mensajes ARP del cable y registra a quien los
// manda, sea del segmento que sea (100, 101, 102…). Solo por cable.
func (m *Monitor) ARPListen() {
	recent := map[string]time.Time{}
	for {
		self, ifi := wiredIface()
		if ifi == nil || arpDisabled.Load() {
			time.Sleep(time.Minute)
			continue
		}
		fd, err := arpSocket(ifi)
		if err != nil {
			time.Sleep(time.Minute)
			continue
		}
		tv := syscall.NsecToTimeval(int64(time.Second))
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		buf := make([]byte, 128)
		until := time.Now().Add(5 * time.Minute) // se reabre cada 5 min por si cambió la interfaz
		for time.Now().Before(until) {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil || n < 28 {
				continue
			}
			sha := net.HardwareAddr(buf[8:14])
			spa := net.IP(buf[14:18]).To4()
			if spa == nil || spa.IsUnspecified() || bytes.Equal(sha, ifi.HardwareAddr) {
				continue
			}
			// pregunta "¿quién tiene X?" dentro de su segmento: la IP por la que más
			// equipos distintos preguntan es la puerta de enlace de ese segmento
			if buf[6] == 0 && buf[7] == 1 {
				tpa := net.IP(buf[24:28]).To4()
				if tpa != nil && !tpa.Equal(spa) && tpa[0] == spa[0] && tpa[1] == spa[1] && tpa[2] == spa[2] {
					m.store.NoteARPRequest(spa.String(), tpa.String())
				}
			}
			mac, ip := strings.ToLower(sha.String()), spa.String()
			k := mac + "@" + ip
			if time.Since(recent[k]) < time.Minute {
				continue
			}
			recent[k] = time.Now()
			m.store.SeenPassive(mac, ip, self.net)
		}
		syscall.Close(fd)
		if len(recent) > 5000 {
			recent = map[string]time.Time{}
		}
	}
}

// arpProbe: ¿está viva esta IP? (ARP probe, sirve para cualquier segmento)
func arpProbe(ip string) bool {
	for try := 0; try < 2; try++ {
		if _, ok := arpPing(ip, "", 700*time.Millisecond); ok {
			return true
		}
	}
	return false
}

// arpSweep pregunta por ARP a todas las IPs de un segmento /24 ("192.168.101").
// Las respuestas las registra ARPListen.
func arpSweep(prefix string) {
	self, ifi := wiredIface()
	if ifi == nil || arpDisabled.Load() {
		return
	}
	fd, err := arpSocket(ifi)
	if err != nil {
		return
	}
	defer syscall.Close(fd)
	to := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ARP), Ifindex: ifi.Index, Halen: 6}
	copy(to.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	pkt := make([]byte, 28)
	pkt[1], pkt[2], pkt[4], pkt[5], pkt[7] = 1, 8, 6, 4, 1
	copy(pkt[8:14], ifi.HardwareAddr)
	copy(pkt[14:18], self.ip.To4())
	for i := 1; i < 255; i++ {
		dst := net.ParseIP(fmt.Sprintf("%s.%d", prefix, i)).To4()
		if dst == nil {
			return
		}
		copy(pkt[24:28], dst)
		syscall.Sendto(fd, pkt, 0, to)
		time.Sleep(5 * time.Millisecond) // sin saturar la red
	}
}
