// snmp_wan.go — detección rápida de "se fue el internet" en el router por SNMP.
//
// Cada 5 s se leen solo 5 contadores del router: estado del puerto de internet
// (eth0) y bytes que entran/salen por él, más lo que entra por el cable local.
// Cuando se va el internet los equipos siguen conectados (ping en verde) y siguen
// intentando salir, pero por el puerto de internet ya no regresa nada:
//
//	puerto de internet abajo                         → "cable": cable o módem
//	bajada casi nula + equipos activos en el local   → "sospecha" (3 lecturas = 15 s)
//	sospecha + la revisión de internet de la Pi falla → "sin": confirmado (proveedor)
//
// Solo en horario (9–18) para la regla de tráfico: fuera de él los equipos se
// apagan y el tráfico baja solo. Un puerto caído se avisa siempre.
package main

import (
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	wanEvery     = 5 * time.Second
	wanLowMbps   = 0.064 // bajada por debajo de esto = "no regresa nada" (64 kb/s)
	wanLanMbps   = 0.064 // lo que mandan los equipos al router por encima de esto = hay gente intentando
	wanUsedMbps  = 1.0   // en los últimos 10 min la bajada promedio pasó de esto (venía con uso)
	wanSuspectN  = 3     // lecturas seguidas para sospechar (15 s)
	wanRecoverN  = 2     // lecturas seguidas con bajada normal para dar por vuelto
	wanHourStart = 9
	wanHourEnd   = 18
)

// SNMPInet: estado del internet del router (va en /api/snmp como "internet").
type SNMPInet struct {
	Estado  string     `json:"estado"` // ok | sospecha | sin | cable | nd (no se sabe)
	Motivo  string     `json:"motivo,omitempty"`
	Desde   *time.Time `json:"desde,omitempty"`
	Bajada  float64    `json:"bajada"` // Mb/s en los últimos 5 s
	Subida  float64    `json:"subida"`
	Local   float64    `json:"local"`  // lo que mandan los equipos al router (Mb/s)
	Rapida  bool       `json:"rapida"` // la lectura de 5 s está funcionando
	Horario bool       `json:"horario"`
}

// confirmador: quién puede decir si el internet de ese router de verdad falla
// (la Store: revisión de internet de la Pi o prueba por segmento).
type inetConfirmer interface {
	RouterInternet(ips []string) (known, down bool, how string)
}

// wanSample: una lectura rápida ya convertida a Mb/s.
type wanSample struct {
	t            time.Time
	up           bool
	in, out, lan float64
	inHours      bool
}

// wanRule: la lógica pura (sin red), para poder probarla.
type wanRule struct {
	state       string // ok | sospecha | sin | cable
	since       time.Time
	low, normal int
	hist        []wanSample // últimos 10 min
	everUp      bool
}

// recentUse: promedio de bajada de los últimos 10 min SIN contar las lecturas bajas
// de la sospecha actual (si no, el propio corte se come el promedio).
func (r *wanRule) recentUse() float64 {
	n, sum := 0, 0.0
	for _, s := range r.hist {
		if s.in >= wanLowMbps {
			sum += s.in
			n++
		}
	}
	if n < 6 { // menos de 30 s de datos con uso
		return 0
	}
	return sum / float64(n)
}

// step aplica una lectura. confirm se llama solo cuando hay sospecha.
// Devuelve el estado nuevo y si cambió.
func (r *wanRule) step(s wanSample, confirm func() (known, down bool, how string)) (string, string, bool) {
	cut := s.t.Add(-10 * time.Minute)
	k := 0
	for k < len(r.hist) && r.hist[k].t.Before(cut) {
		k++
	}
	r.hist = append(r.hist[k:], s)
	prev := r.state
	why := ""
	switch {
	case !s.up:
		if r.everUp || prev == "cable" {
			r.state, why = "cable", "el puerto de internet está abajo: cable o módem del proveedor"
		}
	default:
		r.everUp = true
		lowNow := s.in < wanLowMbps && s.lan >= wanLanMbps
		if lowNow {
			r.low++
			r.normal = 0
		} else {
			r.normal++
			r.low = 0
		}
		switch {
		case prev == "cable":
			r.state = "ok" // volvió el puerto; si sigue sin regresar nada, la regla lo vuelve a ver
		case (prev == "sospecha" || prev == "sin") && r.normal >= wanRecoverN:
			r.state = "ok"
		case prev == "ok" || prev == "":
			r.state = "ok"
			if s.inHours && r.low >= wanSuspectN && r.recentUse() >= wanUsedMbps {
				r.state = "sospecha"
			}
		}
		if r.state == "sospecha" || r.state == "sin" {
			why = fmt.Sprintf("los equipos mandan %.2f Mb/s y por internet regresan %.2f Mb/s", s.lan, s.in)
			if known, down, how := confirm(); known && down {
				r.state, why = "sin", why+"; confirmado: "+how
			} else if r.state == "sin" && known && !down {
				r.state = "sospecha" // la prueba volvió a contestar: queda en duda, no se avisa
			}
		}
	}
	if r.state == "" {
		r.state = "ok"
	}
	if r.state != prev {
		r.since = s.t
		return r.state, why, true
	}
	return r.state, why, false
}

// wanLoop corre la lectura rápida. Empieza cuando la lectura completa ya sabe
// cuál es el puerto de internet y cuál el local.
func (m *SNMPMon) wanLoop() {
	var rule wanRule
	type ctr struct{ in, out, lan uint64 }
	var prev *ctr
	var prevT time.Time
	var downSince time.Time
	announced := false // se avisó "sin internet": falta avisar que volvió
	for {
		time.Sleep(wanEvery)
		m.mu.RLock()
		wan := m.wanIndex(m.state.Ifaces)
		lan, best := 0, -1
		for _, f := range m.state.Ifaces {
			if f.Index != wan && f.Equipos > best {
				lan, best = f.Index, f.Equipos
			}
		}
		name := m.conf.Name
		m.mu.RUnlock()
		if wan == 0 || lan == 0 {
			continue
		}
		g := m.client()
		if g.Connect() != nil {
			continue
		}
		r, err := g.Get([]string{
			fmt.Sprintf("%s.%d", oidIfOper, wan),
			fmt.Sprintf("%s.%d", oidIfHCInOct, wan),
			fmt.Sprintf("%s.%d", oidIfHCOutOct, wan),
			fmt.Sprintf("%s.%d", oidIfHCInOct, lan),
		})
		g.Conn.Close()
		now := time.Now()
		if err != nil || r.Error != gosnmp.NoError || len(r.Variables) != 4 {
			prev = nil // el router no contestó: eso lo cuenta la lectura completa
			m.setInet(func(x *SNMPInet) { x.Rapida = false })
			continue
		}
		v := make([]uint64, 4)
		okAll := true
		for i, p := range r.Variables {
			b := gosnmp.ToBigInt(p.Value)
			if p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance || b == nil || !b.IsUint64() {
				okAll = false
				break
			}
			v[i] = b.Uint64()
		}
		if !okAll {
			continue // sin contadores de 64 bits: no hay lectura rápida
		}
		cur := &ctr{in: v[1], out: v[2], lan: v[3]}
		up := v[0] == 1
		if prev == nil || cur.in < prev.in || cur.out < prev.out || cur.lan < prev.lan {
			prev, prevT = cur, now
			continue
		}
		dt := now.Sub(prevT).Seconds()
		mb := func(d uint64) float64 { return float64(d) * 8 / dt / 1e6 }
		h := now.Hour()
		s := wanSample{t: now, up: up, in: mb(cur.in - prev.in), out: mb(cur.out - prev.out),
			lan: mb(cur.lan - prev.lan), inHours: h >= wanHourStart && h < wanHourEnd}
		prev, prevT = cur, now
		st, why, changed := rule.step(s, func() (bool, bool, string) { return m.confirmInet() })
		m.setInet(func(x *SNMPInet) {
			x.Rapida, x.Horario = true, s.inHours
			x.Bajada, x.Subida, x.Local = round2(s.in), round2(s.out), round2(s.lan)
			x.Estado, x.Motivo = st, why
			if changed {
				t := rule.since
				x.Desde = &t
			}
			if st == "ok" {
				x.Desde, x.Motivo = nil, ""
			}
		})
		if !changed {
			continue
		}
		switch {
		case st == "cable" || st == "sin":
			if !announced {
				downSince = now
			}
			announced = true
			m.event("offline", fmt.Sprintf("%s sin internet: %s", name, why))
		case st == "ok" && announced:
			announced = false
			m.event("online", fmt.Sprintf("%s: volvió el internet (estuvo sin %s)", name, fmtDur(now.Sub(downSince))))
		}
	}
}

func (m *SNMPMon) setInet(f func(*SNMPInet)) {
	m.mu.Lock()
	f(&m.state.Inet)
	m.mu.Unlock()
}

// confirmInet pregunta a la Store con las IPs que tiene el router en sus redes.
func (m *SNMPMon) confirmInet() (known, down bool, how string) {
	c, ok := m.ev.(inetConfirmer)
	if !ok {
		return false, false, ""
	}
	m.mu.RLock()
	ips := []string{m.conf.IP}
	for _, n := range m.extra.nets {
		ips = append(ips, n.ip.String())
	}
	m.mu.RUnlock()
	return c.RouterInternet(ips)
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }
