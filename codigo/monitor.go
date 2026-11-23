package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Monitor struct {
	store     *Store
	fixedNet  string
	interval  time.Duration
	scanEvery time.Duration

	mu       sync.RWMutex
	subnet   string
	lastScan time.Time
	scanning atomic.Bool

	identifying atomic.Bool

	roundDur time.Duration // duración de la última ronda de revisión
	roundN   int
}

func NewMonitor(s *Store, subnet string, interval, scanEvery time.Duration) *Monitor {
	return &Monitor{store: s, fixedNet: subnet, interval: interval, scanEvery: scanEvery}
}

func (m *Monitor) Subnet() string      { m.mu.RLock(); defer m.mu.RUnlock(); return m.subnet }
func (m *Monitor) LastScan() time.Time { m.mu.RLock(); defer m.mu.RUnlock(); return m.lastScan }
func (m *Monitor) Scanning() bool      { return m.scanning.Load() }

func (m *Monitor) Run() {
	m.store.AddEvent("info", "Monitoreo de Red iniciado")
	go m.ARPListen()
	go m.CheckTargets() // internet de inmediato, sin esperar la primera ronda
	go m.WatchInternet()
	go m.WatchSegProbes() // opción A: internet desde cada segmento
	m.Scan()
	tick := time.NewTicker(m.interval)
	scanTick := time.NewTicker(m.scanEvery)
	for {
		select {
		case <-tick.C:
			go m.CheckTargets()
			m.CheckDevices()
		case <-scanTick.C:
			m.Scan()
		}
	}
}

// ---------- escaneo de red ----------

type ifaceInfo struct {
	name string
	ip   net.IP
	net  *net.IPNet
	mac  string
}

func localIface() *ifaceInfo {
	ifs, _ := net.Interfaces()
	var best *ifaceInfo
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "veth") ||
			strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "tailscale") || strings.HasPrefix(i.Name, "wg") {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			if isProbeIP(ipn.IP.To4().String()) {
				continue // IPs de prueba por segmento (monitoreo-segip): no son la IP de la Pi
			}
			info := &ifaceInfo{name: i.Name, ip: ipn.IP.To4(), net: ipn, mac: strings.ToLower(i.HardwareAddr.String())}
			eth := func(n string) bool { return strings.HasPrefix(n, "eth") || strings.HasPrefix(n, "en") }
			if best == nil || eth(i.Name) && !eth(best.name) {
				best = info // prioriza Ethernet sobre Wi-Fi; en cada una, su primera IP
			}
		}
	}
	return best
}

func hostsOf(n *net.IPNet) []string {
	ip := n.IP.To4()
	ones, bits := n.Mask.Size()
	if ip == nil || bits != 32 {
		return nil
	}
	if ones < 22 { // limita a /22 (1022 hosts) para no saturar la Pi
		ones = 22
	}
	mask := net.CIDRMask(ones, 32)
	start := binary.BigEndian.Uint32(ip.Mask(mask))
	size := uint32(1) << (32 - ones)
	var out []string
	for i := uint32(1); i < size-1; i++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, start+i)
		out = append(out, net.IP(b).String())
	}
	return out
}

func (m *Monitor) Scan() {
	if !m.scanning.CompareAndSwap(false, true) {
		return
	}
	defer m.scanning.Store(false)

	var ipnet *net.IPNet
	self := localIface()
	if m.fixedNet != "" {
		_, n, err := net.ParseCIDR(m.fixedNet)
		if err != nil {
			log.Printf("subred inválida %q: %v", m.fixedNet, err)
			return
		}
		ipnet = n
	} else if self != nil {
		ipnet = &net.IPNet{IP: self.net.IP.Mask(self.net.Mask), Mask: self.net.Mask}
	}
	if ipnet == nil {
		log.Printf("no se encontró una interfaz de red activa")
		return
	}
	m.mu.Lock()
	m.subnet = ipnet.String()
	m.mu.Unlock()

	start := time.Now()
	hosts := hostsOf(ipnet)
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			ping(ip, time.Second)
		}(h)
	}
	wg.Wait()

	// Las respuestas (y también los equipos que bloquean ping pero responden ARP)
	// quedan en la tabla ARP del kernel.
	found := 0
	for ip, mac := range readARP() {
		if !ipnet.Contains(net.ParseIP(ip)) {
			continue
		}
		m.store.SeenDevice(mac, ip, lookupHost(ip))
		found++
	}
	if self != nil && self.mac != "" && ipnet.Contains(self.ip) {
		h, _ := os.Hostname()
		m.store.SeenDevice(self.mac, self.ip.String(), h+" (esta Raspberry)")
		found++
	}
	// Quita los equipos de otras redes (p. ej. del Wi‑Fi de la Pi). Solo cuando se
	// escanea por cable o con subred fija: si el cable se cae y la Pi pasa al
	// Wi‑Fi, no se borran los equipos del switch.
	wired := self != nil && (strings.HasPrefix(self.name, "eth") || strings.HasPrefix(self.name, "en"))
	if m.fixedNet != "" || wired {
		m.store.SetSubnet(ipnet.String())
		m.store.PruneOutside(ipnet)
	}
	m.store.PruneStale()
	if wired {
		// barre por ARP todos los segmentos vistos en el cable, el propio incluido
		go func(main *net.IPNet, own net.IP) {
			list := m.store.OtherSegments(main)
			if ip := own.To4(); ip != nil {
				list = append([]string{fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2])}, list...)
			}
			for _, p := range list {
				arpSweep(p)
			}
		}(ipnet, self.ip)
	}
	m.mu.Lock()
	m.lastScan = time.Now()
	m.mu.Unlock()
	log.Printf("escaneo de %s: %d equipos en %s", ipnet, found, time.Since(start).Round(time.Millisecond))
	go m.IdentifyPending()
}

// IdentifyPending busca pistas de los equipos nuevos o con datos viejos.
func (m *Monitor) IdentifyPending() {
	if !m.identifying.CompareAndSwap(false, true) {
		return
	}
	defer m.identifying.Store(false)
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for _, d := range m.store.NeedIdentify() {
		wg.Add(1)
		sem <- struct{}{}
		go func(d Device) {
			defer wg.Done()
			defer func() { <-sem }()
			m.store.SetIdentity(d.ID, identify(d.IP, d.MAC, d.Vendor, d.Hostname))
		}(d)
	}
	wg.Wait()
}

// IdentifyOne vuelve a identificar un equipo (botón "Identificar de nuevo").
func (m *Monitor) IdentifyOne(mac string) {
	if d, ok := m.store.Device(mac); ok {
		m.store.SetIdentity(mac, identify(d.IP, d.MAC, d.Vendor, d.Hostname))
	}
}

func readARP() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // encabezado
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		flags, mac := fields[2], strings.ToLower(fields[3])
		if flags == "0x0" || mac == "00:00:00:00:00:00" {
			continue // entrada incompleta
		}
		out[fields[0]] = mac
	}
	return out
}

func lookupHost(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// ---------- chequeos periódicos ----------

// CheckDevices revisa TODOS los equipos de TODOS los segmentos igual, cada 30 s:
// ARP primero (va directo por el cable, no pasa por el router: 1,200 pings cada
// 30 s hacían que el router limitara sus respuestas y salieran falsas caídas) y
// ping de respaldo (para los que no contestan ARP desde otro segmento).
//
// Los chequeos se reparten a lo largo de 3/4 del intervalo: cada equipo tiene su
// propio momento fijo dentro de la ronda (según su id), así no salen los 1,100 de
// golpe, no hay picos en la red y la latencia no sale inflada por nuestro tráfico.
func (m *Monitor) CheckDevices() {
	start := time.Now()
	devs := m.store.DeviceList()
	vis := devs[:0]
	for _, d := range devs {
		if !segHidden(segOf(d.IP)) { // segmentos ocultos: no se revisan
			vis = append(vis, d)
		}
	}
	devs = vis
	spread := m.interval * 3 / 4
	offs := make(map[string]time.Duration, len(devs))
	for _, d := range devs {
		offs[d.ID] = checkOffset(d.ID, spread)
	}
	sort.Slice(devs, func(i, j int) bool { return offs[devs[i].ID] < offs[devs[j].ID] })
	var wg sync.WaitGroup
	sem := make(chan struct{}, 96)
	arp := readARP()
	for _, d := range devs {
		if wait := time.Until(start.Add(offs[d.ID])); wait > 0 {
			time.Sleep(wait)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d Device) {
			defer wg.Done()
			defer func() { <-sem }()
			var ms float64 = -1
			ok := false
			for try := 0; try < 2 && !ok && !arpDisabled.Load(); try++ {
				ms, ok = arpPing(d.IP, d.MAC, 700*time.Millisecond)
			}
			viaARP := ok
			if !ok {
				ms, ok = ping(d.IP, 1500*time.Millisecond)
				if !ok && arpDisabled.Load() {
					// sin permisos para ARP directo: método anterior (tabla del sistema)
					if mac, in := arp[d.IP]; in && mac == d.MAC && arpReachable(d.IP) {
						ok, ms, viaARP = true, 0, true
					}
				}
			}
			m.store.DevicePing(d.ID, ms, ok, viaARP)
		}(d)
	}
	wg.Wait()
	m.checkGateways()
	m.store.EvalSegments(time.Now())
	m.mu.Lock()
	m.roundDur, m.roundN = time.Since(start), len(devs)
	m.mu.Unlock()
}

// checkOffset: momento fijo de cada equipo dentro de la ronda (0 ≤ x < spread).
func checkOffset(id string, spread time.Duration) time.Duration {
	if spread <= 0 {
		return 0
	}
	h := fnv.New64a()
	h.Write([]byte(id))
	return time.Duration(h.Sum64() % uint64(spread))
}

// checkGateways revisa la puerta de enlace de cada segmento (ARP probe: contesta
// aunque la Pi esté en otro segmento).
func (m *Monitor) checkGateways() {
	var wg sync.WaitGroup
	cands := m.store.GatewayCandidates()
	m.store.PruneGateways(cands)
	for seg, ip := range cands {
		wg.Add(1)
		go func(seg, ip string) {
			defer wg.Done()
			ok := arpProbe(ip)
			if !ok { // si no contestó ARP, ping por el cable
				_, ok = pingVia(ip, 1500*time.Millisecond, "")
			}
			m.store.SetGateway(seg, ip, ok)
		}(seg, ip)
	}
	wg.Wait()
}

// Round: cuánto tardó la última ronda de revisión y a cuántos equipos revisó.
func (m *Monitor) Round() (time.Duration, int, time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.roundDur, m.roundN, m.interval
}

func arpReachable(ip string) bool {
	out, err := exec.Command("ip", "neigh", "show", ip).Output()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "REACHABLE") || strings.Contains(s, "DELAY")
}

// CheckTargets revisa internet y servicios SALIENDO POR EL CABLE (la red que se
// vigila). Si no, cuando el internet del switch se cae, Linux manda la revisión
// por el Wi‑Fi de la Pi (otro módem) y parecería que hay internet.
func (m *Monitor) CheckTargets() {
	iface := ""
	if self := localIface(); self != nil && (strings.HasPrefix(self.name, "eth") || strings.HasPrefix(self.name, "en")) {
		iface = self.name
	}
	var wg sync.WaitGroup
	for _, t := range m.store.Targets() {
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			var ms float64
			var ok bool
			if t.Port > 0 {
				ms, ok = tcpCheckVia(t.Host, t.Port, 3*time.Second, iface)
			} else {
				ms, ok = pingVia(t.Host, 2*time.Second, iface)
			}
			m.store.TargetResult(t.ID, ms, ok)
		}(t)
	}
	wg.Wait()
}

// WatchInternet: revisión rápida y aparte del internet (cada 5 s), para que los
// cortes cortos no se escapen entre las revisiones de 30 s. Sale por el cable.
func (m *Monitor) WatchInternet() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for range tick.C {
		iface := ""
		if self := localIface(); self != nil && (strings.HasPrefix(self.name, "eth") || strings.HasPrefix(self.name, "en")) {
			iface = self.name
		}
		var ok atomic.Bool
		var wg sync.WaitGroup
		for _, h := range []string{"8.8.8.8", "1.1.1.1"} {
			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				if _, r := pingVia(h, 2*time.Second, iface); r {
					ok.Store(true)
				}
			}(h)
		}
		wg.Wait()
		m.store.InternetSample(ok.Load())
	}
}

// ---------- primitivas ----------

var reTime = regexp.MustCompile(`time[=<]([\d.]+)\s*ms`)

// ping usa el comando del sistema (no necesita permisos especiales).
func ping(host string, timeout time.Duration) (float64, bool) { return pingVia(host, timeout, "") }

// pingVia: con iface, el ping sale obligatoriamente por esa interfaz (-I eth0).
func pingVia(host string, timeout time.Duration, iface string) (float64, bool) {
	secs := int(timeout.Seconds())
	if secs < 1 {
		secs = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	args := []string{"-n", "-c", "1", "-W", strconv.Itoa(secs)}
	if iface != "" {
		args = append(args, "-I", iface)
	}
	cmd := exec.CommandContext(ctx, "ping", append(args, host)...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return -1, false
	}
	if m := reTime.FindSubmatch(out); m != nil {
		v, _ := strconv.ParseFloat(string(m[1]), 64)
		return v, true
	}
	return 0, true
}

func tcpCheck(host string, port int, timeout time.Duration) (float64, bool) {
	return tcpCheckVia(host, port, timeout, "")
}

// tcpCheckVia: con iface, la conexión sale obligatoriamente por esa interfaz.
func tcpCheckVia(host string, port int, timeout time.Duration, iface string) (float64, bool) {
	start := time.Now()
	d := net.Dialer{Timeout: timeout, Control: bindToDevice(iface)}
	c, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return -1, false
	}
	c.Close()
	return float64(time.Since(start).Microseconds()) / 1000, true
}

func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	return binary.BigEndian.Uint32(ia) < binary.BigEndian.Uint32(ib)
}

// Tabla reducida de fabricantes (prefijo OUI) más comunes.
var ouiTable = map[string]string{
	"b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "88:a2:9e": "Raspberry Pi", "28:cd:c1": "Raspberry Pi", "e4:5f:01": "Raspberry Pi", "d8:3a:dd": "Raspberry Pi", "2c:cf:67": "Raspberry Pi",
	"00:50:56": "VMware", "00:0c:29": "VMware", "08:00:27": "VirtualBox", "00:15:5d": "Microsoft Hyper-V",
	"3c:5a:b4": "Google", "f4:f5:d8": "Google", "54:60:09": "Google", "f0:ef:86": "Google",
	"fc:fb:fb": "Cisco", "00:1b:54": "Cisco", "00:1e:13": "Cisco", "70:ca:9b": "Cisco",
	"00:18:0a": "Cisco Meraki", "e0:55:3d": "Cisco Meraki",
	"f4:f2:6d": "TP-Link", "50:c7:bf": "TP-Link", "ec:08:6b": "TP-Link", "98:da:c4": "TP-Link", "60:32:b1": "TP-Link", "b0:4e:26": "TP-Link",
	"00:1d:0f": "TP-Link", "c4:6e:1f": "TP-Link", "a4:2b:b0": "TP-Link",
	"74:ac:b9": "Ubiquiti", "24:5a:4c": "Ubiquiti", "fc:ec:da": "Ubiquiti", "78:8a:20": "Ubiquiti", "f0:9f:c2": "Ubiquiti", "b4:fb:e4": "Ubiquiti",
	"00:1a:2b": "Ayecom", "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM",
	"00:0d:3a": "Microsoft", "28:18:78": "Microsoft", "7c:1e:52": "Microsoft",
	"3c:22:fb": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple", "ac:bc:32": "Apple", "88:66:5a": "Apple", "bc:d0:74": "Apple", "8c:85:90": "Apple",
	"00:1c:b3": "Apple", "d0:81:7a": "Apple", "f8:ff:c2": "Apple",
	"9c:b6:d0": "Rivet/Killer", "b4:2e:99": "Giga-Byte", "1c:69:7a": "Elitegroup", "00:d8:61": "Micro-Star (MSI)",
	"30:9c:23": "Micro-Star (MSI)", "d8:bb:c1": "Micro-Star (MSI)", "04:d9:f5": "ASUSTek", "2c:fd:a1": "ASUSTek", "10:7b:44": "ASUSTek",
	"f8:32:e4": "ASUSTek", "e0:d5:5e": "Giga-Byte", "00:23:24": "Giga-Byte",
	"3c:d9:2b": "HP", "9c:8e:99": "HP", "a0:d3:c1": "HP", "ec:b1:d7": "HP", "00:21:5a": "HP", "70:5a:0f": "HP", "c8:d9:d2": "HP",
	"f4:8e:38": "Dell", "18:db:f2": "Dell", "b8:ca:3a": "Dell", "d4:be:d9": "Dell", "00:14:22": "Dell", "54:bf:64": "Dell",
	"00:21:cc": "Lenovo", "e8:6a:64": "Lenovo", "8c:16:45": "Lenovo", "54:ee:75": "Lenovo", "98:fa:9b": "Lenovo",
	"00:80:77": "Brother", "30:05:5c": "Brother", "00:1b:a9": "Brother", "00:00:48": "Epson", "64:eb:8c": "Epson", "00:26:ab": "Epson",
	"00:00:aa": "Xerox", "00:1e:8f": "Canon", "18:0c:ac": "Canon", "00:17:c8": "Kyocera",
	"5c:f3:70": "Samsung", "8c:77:12": "Samsung", "a0:cc:2b": "Samsung", "f0:25:b7": "Samsung", "34:14:5f": "Samsung",
	"28:6c:07": "Xiaomi", "64:09:80": "Xiaomi", "78:11:dc": "Xiaomi", "50:8f:4c": "Xiaomi",
	"00:e0:fc": "Huawei", "48:46:fb": "Huawei", "88:53:d4": "Huawei", "e0:24:7f": "Huawei",
	"00:11:32": "Synology", "00:08:9b": "QNAP", "24:5e:be": "QNAP",
	"cc:2d:e0": "MikroTik", "4c:5e:0c": "MikroTik", "6c:3b:6b": "MikroTik", "b8:69:f4": "MikroTik", "e4:8d:8c": "MikroTik", "48:8f:5a": "MikroTik",
	"00:09:0f": "Fortinet", "90:6c:ac": "Fortinet", "70:4c:a5": "Fortinet",
	"00:1b:17": "Palo Alto", "00:86:9c": "Palo Alto",
	"00:24:a5": "Buffalo", "c0:56:27": "Belkin", "94:10:3e": "Belkin",
	"a0:40:a0": "Netgear", "c0:3f:0e": "Netgear", "9c:3d:cf": "Netgear", "28:c6:8e": "Netgear",
	"00:90:a9": "Western Digital", "00:14:ee": "Western Digital",
	"18:fe:34": "Espressif (IoT)", "24:0a:c4": "Espressif (IoT)", "30:ae:a4": "Espressif (IoT)", "a4:cf:12": "Espressif (IoT)", "84:cc:a8": "Espressif (IoT)",
	"68:ff:7b": "TP-Link", "00:0e:c6": "ASIX", "00:12:17": "Cisco-Linksys", "00:25:9c": "Cisco-Linksys",
	"44:d9:e7": "Ubiquiti", "e0:63:da": "Ubiquiti", "00:04:f2": "Polycom", "64:16:7f": "Polycom",
	"80:5e:c0": "Yealink", "24:9a:d8": "Yealink", "00:15:65": "Yealink", "00:0b:82": "Grandstream", "c0:74:ad": "Grandstream",
	"ac:84:c6": "TP-Link", "e8:48:b8": "TP-Link", "d8:07:b6": "TP-Link", "5c:62:8b": "TP-Link",
	"bc:24:11": "Proxmox", "02:42:ac": "Docker",
	"58:38:79": "Ricoh", "04:18:d6": "Ubiquiti",
}

// Base completa de fabricantes del sistema, si está instalada
// (paquete ieee-data, arp-scan o nmap). install.sh intenta instalar ieee-data.
var (
	ouiOnce sync.Once
	ouiFile map[string]string // "e073e7" -> "HP Inc."
)

func loadOUIFile() {
	ouiFile = map[string]string{}
	paths := []string{
		"/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt",
		"/usr/share/arp-scan/ieee-oui.txt", "/usr/share/nmap/nmap-mac-prefixes",
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			// oui.txt:  "E0-73-E7   (hex)		HP Inc."
			if i := strings.Index(line, "(hex)"); i > 0 {
				k := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(line[:i]), "-", ""))
				if len(k) == 6 {
					ouiFile[k] = strings.TrimSpace(line[i+5:])
				}
				continue
			}
			// ieee-oui.txt / nmap: "E073E7<tab o espacio>HP Inc."
			fs := strings.Fields(line)
			if len(fs) >= 2 && len(fs[0]) == 6 && !strings.HasPrefix(line, "#") {
				if _, err := strconv.ParseUint(fs[0], 16, 32); err == nil {
					name := strings.Join(fs[1:], " ")
					name = strings.TrimSpace(strings.TrimPrefix(name, "(base 16)"))
					if name != "" {
						ouiFile[strings.ToLower(fs[0])] = name
					}
				}
			}
		}
		f.Close()
		if len(ouiFile) > 0 {
			log.Printf("base de fabricantes: %d entradas de %s", len(ouiFile), p)
			return
		}
	}
}

func vendorOf(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	if v, ok := ouiTable[mac[:8]]; ok {
		return v
	}
	ouiOnce.Do(loadOUIFile)
	if v, ok := ouiFile[strings.ReplaceAll(mac[:8], ":", "")]; ok {
		return v
	}
	// segundo bit del primer octeto = MAC aleatoria/privada (celulares modernos)
	if b, err := strconv.ParseUint(mac[:2], 16, 8); err == nil && b&0x02 != 0 {
		return "MAC privada (aleatoria)"
	}
	return ""
}
