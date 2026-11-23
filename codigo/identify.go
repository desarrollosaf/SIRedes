package main

// Identificación de equipos desconocidos: junta "pistas" (nombre NetBIOS de
// Windows, nombre mDNS/Bonjour, puertos abiertos, título de su página web)
// y deduce un tipo probable. Todo con la biblioteca estándar.

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type IDInfo struct {
	NetBIOS  string
	MDNS     string
	Ports    []int
	WebTitle string
	Kind     string
}

// puertos que delatan el tipo de equipo
var probePorts = []int{
	21, 22, 23, 53, 80, 135, 139, 443, 445, 515, 548, 554, 631, 1883, 3389,
	5000, 5060, 7000, 8000, 8008, 8009, 8080, 8443, 9100, 37777, 62078,
}

func identify(ip, mac, vendor, hostname string) IDInfo {
	var info IDInfo
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(3)
	go func() { defer wg.Done(); n := netbiosName(ip); mu.Lock(); info.NetBIOS = n; mu.Unlock() }()
	go func() { defer wg.Done(); n := mdnsName(ip); mu.Lock(); info.MDNS = n; mu.Unlock() }()
	go func() {
		defer wg.Done()
		var pwg sync.WaitGroup
		for _, p := range probePorts {
			pwg.Add(1)
			go func(p int) {
				defer pwg.Done()
				c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(p)), 700*time.Millisecond)
				if err == nil {
					c.Close()
					mu.Lock()
					info.Ports = append(info.Ports, p)
					mu.Unlock()
				}
			}(p)
		}
		pwg.Wait()
	}()
	wg.Wait()
	sort.Ints(info.Ports)

	for _, p := range []int{80, 443, 8080, 8443, 8000} {
		if hasPort(info.Ports, p) {
			if t := webTitle(ip, p); t != "" {
				info.WebTitle = t
				break
			}
		}
	}
	info.Kind = guessKind(ip, mac, vendor, hostname, info)
	return info
}

func hasPort(ps []int, p int) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

// ---------- tipo probable ----------

func guessKind(ip, mac, vendor, hostname string, i IDInfo) string {
	v := strings.ToLower(vendor + " " + hostname + " " + i.WebTitle + " " + i.MDNS + " " + i.NetBIOS)
	has := func(ps ...int) bool {
		for _, p := range ps {
			if hasPort(i.Ports, p) {
				return true
			}
		}
		return false
	}
	contains := func(words ...string) bool {
		for _, w := range words {
			if strings.Contains(v, w) {
				return true
			}
		}
		return false
	}
	winName := regexp.MustCompile(`^(desktop|laptop|pc|win)-`)
	switch {
	case winName.MatchString(strings.ToLower(hostname)) || winName.MatchString(strings.ToLower(i.NetBIOS)):
		return "windows" // nombre típico de Windows (DESKTOP-XXXX)
	case isGateway(ip) || contains("gpon", "modem", "módem", "infinitum", "edgeos", "edgerouter", "routerboard"):
		return "router"
	case contains("raspberry"):
		return "raspberry"
	case has(9100, 631, 515) || contains("printer", "laserjet", "epson", "brother", "kyocera", "canon", "xerox", "ricoh", "impresora") ||
		strings.HasPrefix(strings.ToLower(hostname), "rnp"): // RNP… = impresoras Ricoh
		return "impresora"
	case has(554, 37777) || contains("hikvision", "dahua", "camera", "camara", "cámara", "nvr", "dvr"):
		return "camara"
	case has(5060) || contains("yealink", "grandstream", "polycom", "voip"):
		return "telefono-ip"
	case has(62078) || contains("iphone", "ipad"):
		return "iphone"
	case has(8008, 8009) || contains("chromecast", "smart tv", "android tv", "androidtv", "roku", "bravia", "webos"):
		return "tv"
	case contains("synology", "qnap", "nas", "western digital"):
		return "nas"
	case contains("ubiquiti", "mikrotik", "tp-link", "cisco", "meraki", "netgear", "fortinet", "router", "switch", "access point", "unifi", "omada"):
		return "red"
	case has(3389, 135) || (has(445, 139) && i.NetBIOS != ""):
		return "windows"
	case has(548) || contains("macbook", "imac", "mac mini", "apple"):
		return "mac"
	case contains("espressif", "esp_", "esp-", "tasmota", "shelly", "tuya") || has(1883):
		return "iot"
	case vendor == "MAC privada (aleatoria)":
		return "celular"
	case contains("samsung", "xiaomi", "huawei", "android", "galaxy", "redmi", "motorola"):
		return "celular"
	case has(22) && !has(445):
		return "linux"
	case i.NetBIOS != "" || has(445, 139):
		return "windows"
	case contains("vmware", "virtualbox", "hyper-v", "qemu", "proxmox", "docker"):
		return "virtual"
	case contains("dell", "hp", "lenovo", "asustek", "giga-byte", "micro-star", "intel", "realtek"):
		return "pc"
	}
	return ""
}

// ---------- puerta de enlace ----------

// defaultGateways: puertas de enlace de las redes de la Pi (cable y Wi‑Fi).
func defaultGateways() []string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 3 || p[1] != "00000000" {
			continue
		}
		if b, err := hex.DecodeString(p[2]); err == nil && len(b) == 4 {
			out = append(out, net.IPv4(b[3], b[2], b[1], b[0]).String())
		}
	}
	return out
}

// isGateway: ¿es la puerta de enlace de alguna de las redes de la Pi (cable o Wi‑Fi)?
func isGateway(ip string) bool {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 3 || p[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(p[2])
		if err != nil || len(b) != 4 {
			continue
		}
		if net.IPv4(b[3], b[2], b[1], b[0]).String() == ip {
			return true
		}
	}
	return false
}

// ---------- NetBIOS (nombre de equipos Windows) ----------

func netbiosName(ip string) string {
	c, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	q := []byte{0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20}
	name := append([]byte{'*'}, make([]byte, 15)...)
	for _, b := range name {
		q = append(q, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	q = append(q, 0, 0, 0x21, 0, 1)
	c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := c.Write(q); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil || n < 57 {
		return ""
	}
	buf = buf[:n]
	off := 56 // encabezado(12) + nombre(34) + tipo/clase/ttl/longitud(10)
	count := int(buf[off])
	off++
	for k := 0; k < count && off+18 <= len(buf); k++ {
		e := buf[off : off+18]
		off += 18
		suffix, flags := e[15], binary.BigEndian.Uint16(e[16:18])
		if suffix == 0x00 && flags&0x8000 == 0 { // nombre único de estación
			return strings.TrimSpace(strings.TrimRight(string(e[:15]), "\x00"))
		}
	}
	return ""
}

// ---------- mDNS / Bonjour (iPhone, Mac, Linux, impresoras) ----------

func mdnsName(ip string) string {
	p := net.ParseIP(ip).To4()
	if p == nil {
		return ""
	}
	c, err := net.DialTimeout("udp", net.JoinHostPort(ip, "5353"), time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	q := []byte{0x42, 0x42, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range []string{fmt.Sprint(p[3]), fmt.Sprint(p[2]), fmt.Sprint(p[1]), fmt.Sprint(p[0]), "in-addr", "arpa"} {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 12, 0, 1) // PTR, IN
	c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := c.Write(q); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	buf = buf[:n]
	qd, an := binary.BigEndian.Uint16(buf[4:6]), binary.BigEndian.Uint16(buf[6:8])
	off := 12
	for i := 0; i < int(qd); i++ {
		_, off = dnsName(buf, off)
		off += 4
	}
	for i := 0; i < int(an) && off+10 <= len(buf); i++ {
		_, off = dnsName(buf, off)
		if off+10 > len(buf) {
			break
		}
		typ := binary.BigEndian.Uint16(buf[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
		off += 10
		if typ == 12 {
			name, _ := dnsName(buf, off)
			return strings.TrimSuffix(strings.TrimSuffix(name, "."), ".local")
		}
		off += rdlen
	}
	return ""
}

// dnsName lee un nombre DNS (con compresión) y devuelve el nombre y el
// desplazamiento siguiente.
func dnsName(b []byte, off int) (string, int) {
	var parts []string
	next, jumped := -1, 0
	for off < len(b) && jumped < 10 {
		l := int(b[off])
		switch {
		case l == 0:
			off++
			if next < 0 {
				next = off
			}
			return strings.Join(parts, "."), next
		case l&0xc0 == 0xc0:
			if off+1 >= len(b) {
				return strings.Join(parts, "."), len(b)
			}
			if next < 0 {
				next = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3fff)
			jumped++
		default:
			if off+1+l > len(b) {
				return strings.Join(parts, "."), len(b)
			}
			parts = append(parts, string(b[off+1:off+1+l]))
			off += 1 + l
		}
	}
	if next < 0 {
		next = len(b)
	}
	return strings.Join(parts, "."), next
}

// ---------- título de la página web del equipo ----------

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func webTitle(ip string, port int) string {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	cl := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // solo leemos el título
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := cl.Get(fmt.Sprintf("%s://%s:%d/", scheme, ip, port))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if m := reTitle.FindSubmatch(body); m != nil {
		t := strings.Join(strings.Fields(string(m[1])), " ")
		if len(t) > 80 {
			t = t[:80]
		}
		return t
	}
	if s := resp.Header.Get("Server"); s != "" {
		return "Servidor: " + s
	}
	return ""
}
