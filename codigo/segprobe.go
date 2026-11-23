package main

// Opción A: internet REAL de cada segmento. monitoreo-segip (root) pone una IP de
// la Pi en cada segmento con su propia ruta de salida y deja la lista en
// /run/monitoreo/segprobe.list ("segmento ip puerta"). Aquí, DESDE cada una de
// esas IPs (sale por el router de ese segmento, como una PC de ahí):
//   - cada 10 s: ping a 8.8.8.8 / 1.1.1.1
//   - cada 60 s: DNS (resolver un nombre) y web (abrir una página https)

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const segProbeFile = "/run/monitoreo/segprobe.list"

type segProbe struct{ Seg, IP, GW string }

var (
	probeMu   sync.RWMutex
	probeList []segProbe
	probeIPs  = map[string]bool{}
)

// loadProbes vuelve a leer la lista (la cambia monitoreo-segip).
func loadProbes() []segProbe {
	var list []segProbe
	ips := map[string]bool{}
	if f, err := os.Open(segProbeFile); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Fields(sc.Text())
			if len(p) >= 3 && !strings.HasPrefix(p[0], "#") {
				list = append(list, segProbe{p[0], p[1], p[2]})
				ips[p[1]] = true
			}
		}
		f.Close()
	}
	probeMu.Lock()
	probeList, probeIPs = list, ips
	probeMu.Unlock()
	return list
}

// isProbeIP: IP de prueba de la propia Pi (no es un equipo ni una puerta).
func isProbeIP(ip string) bool {
	probeMu.RLock()
	defer probeMu.RUnlock()
	return probeIPs[ip]
}

// WatchSegProbes: prueba el internet de cada segmento con IP de prueba.
func (m *Monitor) WatchSegProbes() {
	loadProbes()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for n := 0; ; n++ {
		<-tick.C
		full := n%6 == 0 // DNS y web cada 60 s
		var wg sync.WaitGroup
		for _, p := range loadProbes() {
			wg.Add(1)
			go func(p segProbe) {
				defer wg.Done()
				ok := false
				for _, h := range []string{"8.8.8.8", "1.1.1.1"} {
					if _, r := pingVia(h, 2*time.Second, p.IP); r {
						ok = true
						break
					}
				}
				m.store.SegProbeSample(p.Seg, p.GW, ok)
				if full {
					dns := dnsFrom(p.IP)
					web := dns && webFrom(p.IP)
					m.store.SegProbeWeb(p.Seg, dns, web)
				}
			}(p)
		}
		wg.Wait()
	}
}

// resolverFrom: resolver de DNS que pregunta a 8.8.8.8 / 1.1.1.1 saliendo desde src.
func resolverFrom(src string) *net.Resolver {
	servers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var err error
		for _, srv := range servers {
			var local net.Addr = &net.UDPAddr{IP: net.ParseIP(src)}
			if strings.HasPrefix(network, "tcp") {
				local = &net.TCPAddr{IP: net.ParseIP(src)}
			}
			d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: local}
			var c net.Conn
			if c, err = d.DialContext(ctx, network, srv); err == nil {
				return c, nil
			}
		}
		return nil, err
	}}
}

// dnsFrom: ¿se resuelven nombres desde el segmento?
func dnsFrom(src string) bool {
	r := resolverFrom(src)
	for _, h := range []string{"www.google.com", "www.cloudflare.com"} {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		ips, err := r.LookupHost(ctx, h)
		cancel()
		if err == nil && len(ips) > 0 {
			return true
		}
	}
	return false
}

// webFrom: ¿abre una página https desde el segmento? (páginas de "hay internet"
// que contestan 204 sin contenido)
func webFrom(src string) bool {
	d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Resolver: resolverFrom(src)}
	tr := &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: 5 * time.Second, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, u := range []string{"https://www.google.com/generate_204", "https://cp.cloudflare.com/generate_204"} {
		resp, err := cl.Get(u)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 204 {
				return true
			}
		}
	}
	return false
}

type probeState struct {
	GW       string
	OK       bool // ping
	Fails    int
	Ever     bool // alguna vez salió a internet (si nunca, no prueba nada)
	At       time.Time
	DNS, Web bool // última prueba de DNS y web
	WebFails int  // pruebas de web seguidas fallidas (cada 60 s)
	WebEver  bool
	WebAt    time.Time
}

// SegProbeSample guarda el resultado del ping de un segmento.
func (s *Store) SegProbeSample(seg, gw string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.probes == nil {
		s.probes = map[string]*probeState{}
	}
	p := s.probes[seg]
	if p == nil || p.GW != gw {
		p = &probeState{GW: gw}
		s.probes[seg] = p
	}
	p.OK, p.At = ok, time.Now()
	if ok {
		p.Fails, p.Ever = 0, true
	} else {
		p.Fails++
	}
}

// SegProbeWeb guarda el resultado de DNS y web de un segmento.
func (s *Store) SegProbeWeb(seg string, dns, web bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.probes[seg]
	if p == nil {
		return
	}
	p.DNS, p.Web, p.WebAt = dns, web, time.Now()
	if web {
		p.WebFails, p.WebEver = 0, true
	} else {
		p.WebFails++
	}
}

// probeLocked: prueba vigente de un segmento (reciente y que alguna vez funcionó).
func (s *Store) probeLocked(seg string) *probeState {
	p := s.probes[seg]
	if p == nil || !p.Ever || time.Since(p.At) > time.Minute {
		return nil
	}
	return p
}

// webDown: el ping pasa pero no se navega (DNS o web) 2 pruebas seguidas
// (2 min). Solo cuenta si alguna vez navegó desde ahí (si nunca, puede ser un
// filtro de la red, no una falla).
func (p *probeState) webDown() bool {
	return p.WebEver && p.WebFails >= 2 && time.Since(p.WebAt) < 3*time.Minute
}

// probeWhy: explicación corta para el evento de "sin internet".
func (p *probeState) why() string {
	switch {
	case !p.OK:
		return "no sale a internet por su puerta " + p.GW
	case !p.DNS:
		return "llega a internet pero no resuelve nombres (DNS)"
	default:
		return "llega a internet pero no abre páginas web"
	}
}

// puertaUsuariosLocked: la IP por la que preguntan (ARP) al menos 3 equipos distintos
// del segmento: la puerta que de verdad usan las PCs.
func (s *Store) puertaUsuariosLocked(seg string) string {
	best, n := "", 0
	for ip, from := range s.gwVotes[seg] {
		if isProbeIP(ip) {
			continue
		}
		if len(from) > n || (len(from) == n && ip < best) {
			best, n = ip, len(from)
		}
	}
	if n < 3 {
		return ""
	}
	return best
}

// ProbeInfo: resultado de la prueba desde el segmento (para la API).
type ProbeInfo struct {
	Ping      bool   `json:"ping"`
	DNS       bool   `json:"dns"`
	Web       bool   `json:"web"`
	Puerta    string `json:"puerta"`              // por donde sale la prueba
	PuertaPCs string `json:"puertaPCs,omitempty"` // por la que preguntan las PCs (ARP)
}

// RouterInternet: ¿el internet que sale por ese router (cualquiera de sus IPs) falla?
// Primero la revisión de internet de la propia Pi (cada 5 s) si su puerta es ese
// router; si no, la prueba por segmento cuya puerta sea ese router.
func (s *Store) RouterInternet(ips []string) (known, down bool, how string) {
	mine := map[string]bool{}
	for _, ip := range ips {
		mine[ip] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, gw := range defaultGateways() {
		if mine[gw] && s.inetInit {
			if s.inetFails >= 1 || s.inetDown != 0 {
				return true, true, "la Pi tampoco llega a 8.8.8.8 ni 1.1.1.1 por " + gw
			}
			return true, false, ""
		}
	}
	for seg, p := range s.probes {
		if !mine[p.GW] || !p.Ever || time.Since(p.At) > time.Minute {
			continue
		}
		if p.Fails >= 1 {
			return true, true, "la prueba del segmento " + seg + " no llega a internet"
		}
		known = true
	}
	return known, false, ""
}
