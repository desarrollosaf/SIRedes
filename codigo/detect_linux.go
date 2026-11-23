//go:build linux

package main

// detectNetwork: "¿a qué red me conectaron?". Lo usa monitoreo-autoip (como root)
// para que la Pi se ponga sola una IP cuando la red no da IP (sin DHCP).
// Escucha el ARP del cable unos segundos, sin necesitar IP propia, y escribe:
//
//	RED=192.168.10          red /24 con más equipos (o la actual si sigue viva)
//	PUERTA=192.168.10.254   puerta de enlace (la IP por la que más equipos preguntan)
//	MI_RED=si|no             la IP actual sigue sirviendo en esta red
//	CONFLICTO=si|no          otro equipo usa la IP actual
//	LIBRE=192.168.10.200    IP libre para la Pi (la actual si sirve)

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
)

func detectNetwork(ifname, current, curGW string, secs int) int {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil || len(ifi.HardwareAddr) != 6 {
		fmt.Println("ERROR=no_hay_interfaz")
		return 1
	}
	fd, err := arpSocket(ifi)
	if err != nil {
		fmt.Println("ERROR=sin_permisos")
		return 1
	}
	defer syscall.Close(fd)
	cur := net.ParseIP(current).To4()

	hosts := map[string]map[string]bool{}  // "192.168.10" -> IPs vistas
	asked := map[string]map[string]bool{}  // IP preguntada -> equipos que preguntan
	seen := map[string]bool{}              // IPs vistas o preguntadas (ocupadas o reservadas)
	macIPs := map[string]map[string]bool{} // MAC -> IPs con las que se anuncia
	conflictMACs := map[string]bool{}      // MACs que se anuncian con nuestra IP

	tv := syscall.NsecToTimeval(int64(500 * time.Millisecond))
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	buf := make([]byte, 128)
	until := time.Now().Add(time.Duration(secs) * time.Second)
	for time.Now().Before(until) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 28 {
			continue
		}
		sha := net.HardwareAddr(buf[8:14])
		spa := net.IP(buf[14:18]).To4()
		if bytes.Equal(sha, ifi.HardwareAddr) || spa == nil || spa.IsUnspecified() {
			continue
		}
		ms := sha.String()
		if macIPs[ms] == nil {
			macIPs[ms] = map[string]bool{}
		}
		macIPs[ms][spa.String()] = true
		if cur != nil && spa.Equal(cur) {
			conflictMACs[ms] = true // otro equipo anuncia nuestra IP
		}
		p := prefix24(spa)
		if hosts[p] == nil {
			hosts[p] = map[string]bool{}
		}
		hosts[p][spa.String()] = true
		seen[spa.String()] = true
		if buf[6] == 0 && buf[7] == 1 {
			tpa := net.IP(buf[24:28]).To4()
			if tpa != nil && !tpa.Equal(spa) && prefix24(tpa) == p {
				t := tpa.String()
				if asked[t] == nil {
					asked[t] = map[string]bool{}
				}
				asked[t][spa.String()] = true
				seen[t] = true
			}
		}
	}

	gatewayOf := func(p string) string {
		best, bestN := "", 1
		for ip, who := range asked {
			if strings.HasPrefix(ip, p+".") && len(who) > bestN {
				best, bestN = ip, len(who)
			}
		}
		if best != "" {
			return best
		}
		for _, last := range []string{"254", "1"} {
			if probeRaw(fd, ifi, p+"."+last) {
				return p + "." + last
			}
		}
		return ""
	}

	// ¿la IP actual sigue sirviendo? (su red se ve en el cable o su puerta contesta)
	red, puerta, mine := "", "", false
	if cur != nil {
		p := prefix24(cur)
		if len(hosts[p]) >= 2 {
			red, puerta, mine = p, gatewayOf(p), true
		} else if g := gatewayOf(p); g != "" {
			red, puerta, mine = p, g, true
		}
	}
	if red == "" {
		// la red con más equipos distintos
		var ps []string
		for p := range hosts {
			ps = append(ps, p)
		}
		sort.Slice(ps, func(i, j int) bool {
			if len(hosts[ps[i]]) != len(hosts[ps[j]]) {
				return len(hosts[ps[i]]) > len(hosts[ps[j]])
			}
			return ps[i] < ps[j]
		})
		if len(ps) > 0 {
			red = ps[0]
			puerta = gatewayOf(red)
		}
	}
	// Conservador: si en el cable se ven equipos de la red actual, la IP sigue
	// sirviendo. Solo si casi no se ve nada se exige que la puerta configurada exista.
	if mine && cur != nil && len(hosts[prefix24(cur)]) < 2 && curGW != "" && !seen[curGW] &&
		!probeRaw(fd, ifi, curGW) && !probeRaw(fd, ifi, curGW) {
		mine = false
	}
	// Conflicto solo si OTRO equipo se anuncia con nuestra IP (visto en el cable),
	// sin contar routers/proxies que contestan por muchas IPs.
	conflict := false
	for mac := range conflictMACs {
		if len(macIPs[mac]) < 3 {
			conflict = true
		}
	}

	libre := ""
	if mine && !conflict {
		libre = cur.String()
	} else if red != "" {
		// IPs altas primero (.200–.250, luego .199 hacia abajo): las bajas suelen ser fijas
		var cand []int
		for i := 200; i <= 250; i++ {
			cand = append(cand, i)
		}
		for i := 199; i >= 100; i-- {
			cand = append(cand, i)
		}
		for _, i := range cand {
			ip := fmt.Sprintf("%s.%d", red, i)
			if seen[ip] || ip == puerta || (cur != nil && ip == cur.String() && conflict) {
				continue
			}
			if !probeRaw(fd, ifi, ip) && !probeRaw(fd, ifi, ip) {
				libre = ip
				break
			}
		}
	}

	yn := map[bool]string{true: "si", false: "no"}
	fmt.Printf("RED=%s\nPUERTA=%s\nMI_RED=%s\nCONFLICTO=%s\nLIBRE=%s\n", red, puerta, yn[mine], yn[conflict], libre)
	if red == "" {
		return 2 // no se vio ninguna red en el cable
	}
	return 0
}

func prefix24(ip net.IP) string { return fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2]) }

// probeRaw: ARP probe (IP de origen 0.0.0.0) por broadcast; ¿alguien tiene esta IP?
func probeRaw(fd int, ifi *net.Interface, ip string) bool {
	dst := net.ParseIP(ip).To4()
	if dst == nil {
		return false
	}
	pkt := make([]byte, 28)
	pkt[1], pkt[2], pkt[4], pkt[5], pkt[7] = 1, 8, 6, 4, 1
	copy(pkt[8:14], ifi.HardwareAddr)
	copy(pkt[24:28], dst)
	to := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ARP), Ifindex: ifi.Index, Halen: 6}
	copy(to.Addr[:], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	tv := syscall.NsecToTimeval(int64(100 * time.Millisecond))
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if err := syscall.Sendto(fd, pkt, 0, to); err != nil {
		return false
	}
	buf := make([]byte, 128)
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 28 {
			continue
		}
		if buf[6] == 0 && buf[7] == 2 && net.IP(buf[14:18]).Equal(dst) && !bytes.Equal(buf[8:14], ifi.HardwareAddr) {
			return true
		}
	}
	return false
}
