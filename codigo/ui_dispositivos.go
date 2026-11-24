// ui_dispositivos.go — Dispositivos con Go + htmx.
//
//	GET  /dispositivos?q=&f=&seg=&dev=&ip=   página completa; con htmx, solo la lista (#dv-lista)
//	GET  /dispositivos/segmento?seg=&q=&f=   tabla de un segmento (se pide al abrirlo)
//	GET  /dispositivos/equipo?id=            ventana con el detalle del equipo (#modal)
//	GET  /dispositivos/grafica?id=&r=        gráfica de latencia (SVG hecho aquí): 1h, 24h o 7d
//	GET  /dispositivos/editar?id=            ventana para editar (Operador o más)
//	POST /dispositivos/equipo                guardar nombre, ubicación y tipo (Operador o más)
//	GET|POST /dispositivos/escanear          botón "Escanear ahora" (Operador o más)
//
// Mismos datos que /api/devices, /api/segments, /api/history y /api/snmp/equipo, pero con
// Store.Query y funciones de Go directo. Los segmentos son <details>: el contenido de cada uno
// se pide al abrirlo. Cada 30 s se vuelve a pedir la lista y el navegador manda cuáles segmentos
// están abiertos (campos "abierto"), así que nada se cierra solo.
package main

import (
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
	"monitoreo/web"
)

// ---------- íconos (mismos trazos que el panel viejo) ----------

var trazos = map[string]string{
	"router":  `<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M8 9a6 6 0 0 1 8 0M5.5 6.5a10 10 0 0 1 13 0"/>`,
	"chip":    `<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>`,
	"printer": `<path d="M7 8V3h10v5"/><rect x="3" y="8" width="18" height="9" rx="2"/><path d="M7 14h10v7H7z"/>`,
	"camera":  `<rect x="3" y="6" width="13" height="10" rx="2"/><path d="M16 10l5-3v8l-5-3"/>`,
	"voip":    `<path d="M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2z"/>`,
	"phone":   `<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>`,
	"tv":      `<rect x="3" y="5" width="18" height="12" rx="2"/><path d="M8 21h8"/>`,
	"disk":    `<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/>`,
	"pc":      `<rect x="3" y="4" width="18" height="12" rx="1.5"/><path d="M8 20h8M12 16v4"/>`,
	"laptop":  `<rect x="5" y="5" width="14" height="10" rx="1.5"/><path d="M2 19h20"/>`,
	"server":  `<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/>`,
	"help":    `<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5v.7M12 17h.01"/>`,
}

// icono arma un <svg> con trazos fijos de esta tabla (nunca datos del usuario).
func icono(n string) template.HTML {
	p, ok := trazos[n]
	if !ok {
		p = trazos["help"]
	}
	return template.HTML(`<svg class="i" viewBox="0 0 24 24" aria-hidden="true">` + p + `</svg>`)
}

// tipos de equipo: clave que guarda la Pi, nombre y ícono (en el orden de la lista)
var tiposDV = []struct{ Clave, Nombre, Icono string }{
	{"router", "Router / puerta de enlace", "router"}, {"raspberry", "Raspberry Pi", "chip"}, {"impresora", "Impresora", "printer"},
	{"camara", "Cámara IP", "camera"}, {"telefono-ip", "Teléfono IP", "voip"}, {"iphone", "iPhone / iPad", "phone"},
	{"celular", "Celular", "phone"}, {"tv", "TV / Chromecast", "tv"}, {"nas", "Almacenamiento (NAS)", "disk"},
	{"red", "Equipo de red", "router"}, {"windows", "PC con Windows", "pc"}, {"mac", "Mac", "laptop"},
	{"linux", "Linux / servidor", "server"}, {"iot", "Dispositivo inteligente (IoT)", "chip"}, {"virtual", "Máquina virtual", "server"},
	{"pc", "Computadora", "pc"}, {"escritorio", "PC de escritorio", "pc"}, {"laptop", "Laptop", "laptop"},
}

func tipoDe(k string) (nombre, ico string) {
	for _, t := range tiposDV {
		if t.Clave == k {
			return t.Nombre, t.Icono
		}
	}
	return "Tipo desconocido", "help"
}

var puertosDV = map[int]string{21: "FTP", 22: "SSH (acceso remoto Linux)", 23: "Telnet (equipos viejos o de red)", 53: "DNS", 80: "Página web",
	135: "Servicios Windows", 139: "Compartir archivos (NetBIOS)", 443: "Página web segura", 445: "Carpetas compartidas Windows",
	515: "Impresión LPD", 548: "Archivos de Apple", 554: "Video de cámara (RTSP)", 631: "Impresión IPP", 1883: "MQTT (IoT)",
	3389: "Escritorio remoto Windows", 5000: "Web/Synology", 5060: "Telefonía IP (SIP)", 7000: "AirPlay (Apple)",
	8000: "Web/cámara Hikvision", 8008: "Chromecast", 8009: "Chromecast", 8080: "Página web alterna", 8443: "Web segura alterna",
	9100: "Impresora (RAW)", 37777: "Cámara Dahua", 62078: "iPhone/iPad"}

// ---------- datos de la pantalla ----------

type opcionDV struct {
	Valor, Texto string
	Sel, Oculto  bool
}

type chipDV struct{ Clase, Texto, Titulo string }

type barraDV struct{ Clase, X, W string }

type indDV struct{ Clase, Titulo string }

type filaDV struct {
	ID, IP, Nombre, Tipo   string
	Icono                  template.HTML
	EstadoTxt, EstadoClase string
	Cable, Inet            indDV
	Latencia               string
	PorIdent, Alias        bool
}

type segDV struct {
	Seg, Nombre, Sub, Q, F    string
	Abierto, Down, Mal        bool
	Conectados, Desconectados int
	Barra                     []barraDV
	Chips                     []chipDV
	Filas                     []filaDV
}

type datosDV struct {
	Marco               web.Marco
	Q, F, Seg           string
	Demo, Puede         bool
	Escaneando          bool
	Segmentos, Estados  []opcionDV
	Segs                []segDV
	NSegs               int
	Plegar, HayAbiertos bool // botón "Abrir/Cerrar todos" (solo con 2 segmentos o más)
	Vacio               string
	AbrirDev            string
}

type cuerpoDV struct{ Filas []filaDV }

func nombreEquipo(d *Device) string {
	switch {
	case d.Name != "":
		return d.Name
	case d.Hostname != "":
		return d.Hostname
	case d.NetBIOS != "":
		return d.NetBIOS
	case d.MDNS != "":
		return d.MDNS
	case d.Vendor == macPrivada:
		return "Celular (MAC privada)"
	case d.Vendor != "":
		return d.Vendor
	}
	return "Sin nombre"
}

const macPrivada = "MAC privada (aleatoria)"

// estado de un equipo: pend, off, noinet, ok o unk (conectado, internet sin verificar)
func estadoDV(d *Device, nets map[string]string) string {
	switch {
	case d.Health == "pendiente":
		return "pend"
	case !d.Online:
		return "off"
	}
	switch nets[segOf(d.IP)] {
	case "sin":
		return "noinet"
	case "ok":
		return "ok"
	}
	return "unk"
}

// los 3 estados: Conectado, Sin internet y Desconectado (más Revisando)
func textoEstado(e string) (txt, clase string) {
	switch e {
	case "noinet":
		return "Sin internet", "noinet"
	case "off":
		return "Desconectado", "off"
	case "pend":
		return "Revisando", "pend"
	}
	return "Conectado", "ok"
}

func indicadores(e string, nd bool) (cable, inet indDV) {
	c := "ok"
	if e == "off" || e == "pend" {
		c = "off"
	}
	cable = indDV{c, "Cable: conectado"}
	if c == "off" {
		cable.Titulo = "Cable: sin respuesta"
	}
	switch e {
	case "ok":
		inet = indDV{"ok", "Internet: bien"}
	case "noinet":
		inet = indDV{"bad", "Internet: SIN salida en su segmento"}
	case "unk":
		inet = indDV{"unk", "Internet: sin verificar (aún no se encontró la puerta de enlace de su segmento)"}
		if nd {
			inet.Titulo = "Internet: desconocido (la Pi no tiene internet y este segmento sale por otro router)"
		}
	default:
		inet = indDV{"off", "Internet: —"}
	}
	return
}

func filaDe(d Device, nets map[string]string) filaDV {
	e := estadoDV(&d, nets)
	nom, ico := tipoDe(d.Kind)
	f := filaDV{ID: d.ID, IP: d.IP, Nombre: nombreEquipo(&d), Tipo: nom, Icono: icono(ico), Alias: d.Alias, PorIdent: !isIdentified(&d), Latencia: "—"}
	f.EstadoTxt, f.EstadoClase = textoEstado(e)
	f.Cable, f.Inet = indicadores(e, nets[segOf(d.IP)] == "nd")
	if d.Online && d.LatencyMs > 0 {
		f.Latencia = fmt.Sprintf("%.1f ms", d.LatencyMs)
	}
	return f
}

func filasDe(devs []Device, nets map[string]string) []filaDV {
	out := make([]filaDV, 0, len(devs))
	for _, d := range devs {
		out = append(out, filaDe(d, nets))
	}
	return out
}

// red de internet por segmento (ok, sin, nd, ?) según la Pi
func (s *Store) redSegmentos() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[string]string, len(s.segNet))
	for k, v := range s.segNet {
		m[k] = v
	}
	return m
}

// orden de segmentos: números, luego otras redes, al final 169.254
func segPeso(s string) float64 {
	if s == "169.254" {
		return 1e12
	}
	if n, err := strconv.Atoi(s); err == nil {
		return float64(n)
	}
	return float64(ipNum(s+".0")) + 1e3
}

func nombreSeg(g SegSummary) string {
	switch {
	case g.Seg == "169.254":
		return "Sin IP (169.254)"
	case g.Name != "":
		return g.Name + " (" + g.Seg + ")"
	}
	if _, err := strconv.Atoi(g.Seg); err == nil {
		return "Segmento " + g.Seg
	}
	return "Segmento " + g.Seg + ".x"
}

func rangoSeg(s string) string {
	if s == "169.254" {
		return "169.254.x.x"
	}
	if _, err := strconv.Atoi(s); err == nil {
		return "192.168." + s + ".x"
	}
	return s + ".x"
}

func pct(a, total int) string { return strconv.FormatFloat(float64(a)*100/float64(total), 'f', 1, 64) }

// segDe arma la tarjeta de un segmento. filas = equipos que se muestran (nil si está cerrado).
func segDe(g SegSummary, on, off, pend int, abierto bool, filas []filaDV, q, f string) segDV {
	s := segDV{Seg: g.Seg, Nombre: nombreSeg(g), Q: q, F: f, Abierto: abierto, Down: g.Down,
		Mal: g.Down || g.Net == "sin", Conectados: on, Desconectados: off, Filas: filas}
	var partes []string
	if g.Location != "" {
		partes = append(partes, g.Location)
	}
	if g.Gateway != "" {
		partes = append(partes, "puerta ."+g.Gateway[strings.LastIndex(g.Gateway, ".")+1:])
	}
	s.Sub = strings.Join(partes, " · ")
	if s.Sub == "" {
		s.Sub = rangoSeg(g.Seg)
	}
	total := on + off + pend
	if total < 1 {
		total = 1
	}
	x := 0
	add := func(clase string, n int) {
		if n > 0 {
			s.Barra = append(s.Barra, barraDV{clase, pct(x, total), pct(n, total)})
			x += n
		}
	}
	if g.Net == "sin" {
		add("b-noinet", on)
	} else {
		add("b-normal", on)
	}
	add("b-pendiente", pend)
	add("b-off", off)
	switch {
	case g.Net == "sin":
		s.Chips = append(s.Chips, chipDV{"st st-noinet", "Sin internet", ""})
	case g.Net == "ok":
		s.Chips = append(s.Chips, chipDV{"st st-ok", "Internet OK", ""})
	case g.Net == "nd":
		if g.Seg != "169.254" {
			s.Chips = append(s.Chips, chipDV{"st st-pend", "Internet no se sabe", "La Pi no tiene internet y este segmento sale por otro router"})
		}
	case g.GwDead:
		s.Chips = append(s.Chips, chipDV{"st st-off", "Puerta no responde", "La puerta " + g.Gateway + " nunca ha contestado"})
	default:
		s.Chips = append(s.Chips, chipDV{"st st-pend", "Internet sin verificar", ""})
	}
	if pend > 0 {
		s.Chips = append(s.Chips, chipDV{"chip h-pendiente", fmt.Sprintf("revisando %d…", pend), ""})
	}
	return s
}

var filtrosDV = map[string]bool{"": true, "ok": true, "noinet": true, "nd": true, "gone": true, "all": true, "unk": true, "pend": true}

func recortar(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func armarDV(store *Store, q, f, segSel string, abiertos map[string]bool, demo bool) datosDV {
	sums := store.Segments()
	sort.Slice(sums, func(i, j int) bool { return segPeso(sums[i].Seg) < segPeso(sums[j].Seg) })
	if demo && len(sums) > 0 { // ?demo: simula que el segmento más grande cayó (solo en pantalla)
		g := 0
		for i := range sums {
			if sums[i].Present > sums[g].Present {
				g = i
			}
		}
		sums[g].Down, sums[g].DownCount, sums[g].DownSince = true, sums[g].Present, time.Now().Add(-2*time.Minute)
	}
	valido := false
	for _, g := range sums {
		if g.Seg == segSel {
			valido = true
		}
	}
	if !valido {
		segSel = ""
	}
	nets := store.redSegmentos()
	d := datosDV{Q: q, F: f, Seg: segSel, Demo: demo}

	d.Segmentos = append(d.Segmentos, opcionDV{Valor: "", Texto: fmt.Sprintf("Todos los segmentos (%d)", len(sums)), Sel: segSel == ""})
	gone := 0
	for _, g := range sums {
		d.Segmentos = append(d.Segmentos, opcionDV{Valor: g.Seg, Texto: fmt.Sprintf("%s (%d)", nombreSeg(g), g.Present), Sel: segSel == g.Seg})
		gone += g.Health["desconectado"]
	}
	for _, o := range []opcionDV{{Valor: "ok", Texto: "Con internet"}, {Valor: "", Texto: "Conectados"},
		{Valor: "gone", Texto: fmt.Sprintf("Desconectados (%d)", gone)}, {Valor: "nd", Texto: "Internet desconocido"},
		{Valor: "noinet", Texto: "Sin internet"}, {Valor: "all", Texto: "Todos"}, {Valor: "unk", Texto: "Por identificar", Oculto: f != "unk"}} {
		o.Sel = o.Valor == f
		d.Estados = append(d.Estados, o)
	}

	filtrando := q != "" || f != ""
	var grupos map[string][]Device
	if filtrando {
		grupos = map[string][]Device{}
		for _, x := range store.Query(segSel, q, f, false, 1000) {
			grupos[segOf(x.IP)] = append(grupos[segOf(x.IP)], x)
		}
	}
	var lista []SegSummary
	for _, g := range sums {
		if segSel != "" && g.Seg != segSel {
			continue
		}
		if filtrando && len(grupos[g.Seg]) == 0 {
			continue
		}
		lista = append(lista, g)
	}
	for _, g := range lista {
		abierto := segSel != "" || abiertos[g.Seg] || (filtrando && len(lista) == 1)
		var s segDV
		if filtrando {
			rows := grupos[g.Seg]
			on, off, pend := 0, 0, 0
			for _, x := range rows {
				if x.Online {
					on++
				}
				switch x.Health {
				case "desconectado":
					off++
				case "pendiente":
					pend++
				}
			}
			var filas []filaDV
			if abierto {
				filas = filasDe(rows, nets)
			}
			s = segDe(g, on, off, pend, abierto, filas, q, f)
		} else {
			var filas []filaDV
			if abierto {
				filas = filasDe(store.Query(g.Seg, "", "", false, 1000), nets)
			}
			s = segDe(g, g.Online, g.Health["desconectado"], g.Health["pendiente"], abierto, filas, q, f)
		}
		if abierto {
			d.HayAbiertos = true
		}
		d.Segs = append(d.Segs, s)
	}
	d.NSegs = len(d.Segs)
	d.Plegar = d.NSegs >= 2
	switch {
	case filtrando:
		d.Vacio = "Ningún equipo coincide."
	default:
		d.Vacio = "Sin dispositivos."
	}
	return d
}

// ---------- detalle del equipo ----------

type datoDV struct{ K, V string }

type equipoDV struct {
	ID, IP, MAC, Nombre, Tipo, TipoNota string
	Icono                               template.HTML
	EstadoTxt, EstadoClase              string
	Cable, Inet                         indDV
	PorIdent, Puede                     bool
	Datos                               []datoDV
	Latencia, LatenciaClase             string
	Router, RouterTxt, RouterClase      string
	Puertos                             []string
	WebURL, OUI                         string
	MacPrivada, SinFabricante           bool
	Grafica                             graficaDV
}

func fechaDV(t time.Time) string { return t.Format("02/01/2006 15:04:05") }

func equipoDe(store *Store, d Device, puede bool) equipoDV {
	calcHealth(&d, time.Now())
	nets := store.redSegmentos()
	e := estadoDV(&d, nets)
	nom, ico := tipoDe(d.Kind)
	v := equipoDV{ID: d.ID, IP: d.IP, MAC: d.MAC, Nombre: nombreEquipo(&d), Tipo: nom, Icono: icono(ico), PorIdent: !isIdentified(&d), Puede: puede}
	if d.Kind != "" {
		v.TipoNota = " (probable)"
	}
	v.EstadoTxt, v.EstadoClase = textoEstado(e)
	v.Cable, v.Inet = indicadores(e, nets[segOf(d.IP)] == "nd")
	add := func(k, val string) {
		if val != "" {
			v.Datos = append(v.Datos, datoDV{k, val})
		}
	}
	add("Ubicación", d.Location)
	add("Fabricante", d.Vendor)
	add("Nombre en la red", d.Hostname)
	add("Nombre Windows", d.NetBIOS)
	add("Nombre Bonjour", d.MDNS)
	add("Su página web", d.WebTitle)
	switch {
	case !d.Online:
		v.Latencia, v.LatenciaClase = "sin respuesta", "c-bad"
	case d.LatencyMs > 0:
		v.Latencia = fmt.Sprintf("%.1f ms", d.LatencyMs)
	default:
		v.Latencia, v.LatenciaClase = "—", "sub"
	}
	v.Datos = append(v.Datos,
		datoDV{"Pings perdidos (1 h)", fmt.Sprintf("%.1f %%", d.Loss)},
		datoDV{"Caídas (24 h)", strconv.Itoa(d.Drops24h)},
		datoDV{"Visto por 1.ª vez", fechaDV(d.FirstSeen)})
	if !d.Identified.IsZero() {
		v.Datos = append(v.Datos, datoDV{"Revisado", web.Hace(d.Identified)})
	}
	// cable e internet según el router (SNMP); solo si el equipo es de sus redes y el router responde
	if r := SNMPDeviceInfo(d.IP); r.Active && !r.Down {
		v.Router = r.Router
		switch {
		case !r.EnARP:
			v.RouterTxt, v.RouterClase = "no está en su tabla ARP", "sub"
		case strings.EqualFold(r.MAC, d.MAC):
			v.RouterTxt, v.RouterClase = "lo ve", "c-ok"
		default:
			v.RouterTxt, v.RouterClase = "lo tiene con otra MAC: "+r.MAC, "c-warn"
		}
	}
	for _, p := range d.Ports {
		n := puertosDV[p]
		if n == "" {
			n = "?"
		}
		v.Puertos = append(v.Puertos, fmt.Sprintf("%d · %s", p, n))
	}
	for _, p := range d.Ports {
		if p == 80 || p == 8080 || p == 443 || p == 8443 || p == 8000 || p == 5000 {
			esq := "http"
			if p == 443 || p == 8443 {
				esq = "https"
			}
			v.WebURL = esq + "://" + d.IP
			if p != 80 && p != 443 {
				v.WebURL += ":" + strconv.Itoa(p)
			}
			break
		}
	}
	v.MacPrivada = d.Vendor == macPrivada
	v.SinFabricante = d.Vendor == ""
	if len(d.MAC) >= 8 {
		v.OUI = d.MAC[:8]
	}
	v.Grafica = graficaDe(store, d.ID, "1h")
	return v
}

// ---------- gráfica de latencia en SVG ----------

type rangoDV struct {
	R, Etiqueta string
	On          bool
}
type lineaDV struct{ Y, Etiqueta string }
type ejeDV struct{ X, Texto, Ancla string }
type marcaDV struct{ X, W, Clase, Op string }
type huecoDV struct{ X, W string }
type puntoDV struct{ X, W, Titulo string }

type graficaDV struct {
	ID, Rango      string
	Rangos         []rangoDV
	Sin            bool
	Rejilla        []lineaDV
	Eje            []ejeDV
	Marcas         []marcaDV
	Huecos         []huecoDV
	Banda, Linea   string
	Puntos         []puntoDV
	Info           string
	Ancho, Alto, Y string // medidas del dibujo (viewBox) y base de las marcas
}

// Rojo solo para pérdidas SUELTAS; un tramo seguido de 3 o más sin respuesta es apagado: hueco gris (-2).
func tramosSeguidos(v []float64) []float64 {
	out := append([]float64(nil), v...)
	for i := 0; i < len(out); {
		if out[i] != -1 {
			i++
			continue
		}
		j := i
		for j < len(out) && out[j] == -1 {
			j++
		}
		if j-i >= 3 {
			for k := i; k < j; k++ {
				out[k] = -2
			}
		}
		i = j
	}
	return out
}

var diasCortos = [...]string{"dom", "lun", "mar", "mié", "jue", "vie", "sáb"}

func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func graficaDe(store *Store, id, rango string) graficaDV {
	if rango != "24h" && rango != "7d" {
		rango = "1h"
	}
	g := graficaDV{ID: id, Rango: rango, Ancho: "640", Alto: "200"}
	for _, r := range [][2]string{{"1h", "1 h"}, {"24h", "24 h"}, {"7d", "7 días"}} {
		g.Rangos = append(g.Rangos, rangoDV{r[0], r[1], r[0] == rango})
	}
	hist := store.History(id, rango)
	const W, H, L, R, T, B = 640.0, 200.0, 46.0, 8.0, 8.0, 22.0
	w, h := W-L-R, H-T-B
	if len(hist) == 0 {
		g.Sin = true
		g.Info = "Aún no hay datos para este periodo"
		g.Y = f1(T + h/2)
		return g
	}
	// tramos seguidos sin respuesta → gris; rojo solo pérdidas sueltas
	if rango == "1h" {
		av := make([]float64, len(hist))
		for i, p := range hist {
			av[i] = p.Avg
		}
		soft := tramosSeguidos(av)
		for i := range hist {
			if soft[i] == -2 && hist[i].Avg == -1 {
				hist[i].Avg, hist[i].Loss = -2, 0
			}
		}
	} else {
		for i := range hist {
			if hist[i].Loss >= 100 {
				hist[i].Avg, hist[i].Loss = -2, 0
			}
		}
	}
	max := 1.0
	for _, p := range hist {
		max = math.Max(max, p.Max)
	}
	max *= 1.15
	for k := 0; k <= 3; k++ {
		y := T + h - h*float64(k)/3
		et := fmt.Sprintf("%.0f ms", max*float64(k)/3)
		if max < 10 {
			et = fmt.Sprintf("%.1f ms", max*float64(k)/3)
		}
		g.Rejilla = append(g.Rejilla, lineaDV{f1(y), et})
	}
	step, span := 1800.0, 7*86400.0
	switch rango {
	case "1h":
		step, span = 30, 3600
	case "24h":
		span = 86400
	}
	t1 := float64(time.Now().Unix())
	t0 := t1 - span
	X := func(t float64) float64 { return L + math.Max(0, t-t0)/span*w }
	Y := func(v float64) float64 { return T + h - v/max*h }
	fmtT := func(t float64) string {
		tm := time.Unix(int64(t), 0)
		if rango == "7d" {
			return diasCortos[tm.Weekday()] + " " + tm.Format("15:04")
		}
		return tm.Format("15:04")
	}
	g.Eje = []ejeDV{{f1(L), fmtT(t0), "start"}, {f1(X(t0 + span/2)), fmtT(t0 + span/2), "middle"}, {f1(L + w), fmtT(t1), "end"}}

	// pérdidas: franja roja abajo; presente sin latencia: franja verde
	bw := math.Max(2, step/span*w)
	for _, p := range hist {
		x := f1(X(float64(p.T)) - bw/2)
		switch {
		case p.Loss > 0:
			g.Marcas = append(g.Marcas, marcaDV{x, f1(bw), "g-per", strconv.FormatFloat(math.Min(1, 0.35+p.Loss/160), 'f', 2, 64)})
		case p.Avg == 0:
			g.Marcas = append(g.Marcas, marcaDV{x, f1(bw), "g-pre", "0.75"})
		}
	}
	// sombra entre el promedio y el máximo (24 h y 7 días)
	if rango != "1h" {
		var b strings.Builder
		ini := false
		for _, p := range hist {
			if p.Avg <= 0 {
				continue
			}
			c := "L"
			if !ini {
				c, ini = "M", true
			}
			fmt.Fprintf(&b, "%s%s %s ", c, f1(X(float64(p.T))), f1(Y(p.Max)))
		}
		if ini {
			for i := len(hist) - 1; i >= 0; i-- {
				if hist[i].Avg > 0 {
					fmt.Fprintf(&b, "L%s %s ", f1(X(float64(hist[i].T))), f1(Y(hist[i].Avg)))
				}
			}
			b.WriteString("Z")
			g.Banda = b.String()
		}
	}
	// la línea se corta donde no hay datos (equipo desconectado o apagado)
	var ln strings.Builder
	pen, prevT := false, 0.0
	for _, p := range hist {
		t := float64(p.T)
		if p.Avg < 0 || t-prevT > step*2.5 {
			pen = false
		}
		prevT = t
		if p.Avg <= 0 {
			if p.Avg == 0 {
				pen = false
			}
			continue
		}
		c := "L"
		if !pen {
			c = "M"
		}
		fmt.Fprintf(&ln, "%s%s %s ", c, f1(X(t)), f1(Y(p.Avg)))
		pen = true
	}
	g.Linea = strings.TrimSpace(ln.String())
	// tramos desconectados (sin datos): fondo gris claro
	gs, tiene := 0.0, false
	for i, p := range hist {
		off := p.Avg <= -2 || (i > 0 && float64(p.T-hist[i-1].T) > step*2.5)
		if off && !tiene {
			if i > 0 {
				gs = X(float64(hist[i-1].T))
			} else {
				gs = X(float64(p.T))
			}
			tiene = true
		}
		if !off && tiene {
			g.Huecos = append(g.Huecos, huecoDV{f1(gs), f1(X(float64(p.T)) - gs)})
			tiene = false
		}
		if off && tiene && i == len(hist)-1 {
			g.Huecos = append(g.Huecos, huecoDV{f1(gs), f1(X(float64(p.T)) - gs)})
		}
	}
	// hover: un título por periodo
	g.Y = f1(T)
	for _, p := range hist {
		var d string
		switch {
		case p.Avg <= -2:
			d = "desconectado"
		case p.Avg < 0:
			d = "sin respuesta"
		case p.Avg == 0:
			d = "presente (se le escucha en la red; no contesta la revisión)"
		default:
			d = fmt.Sprintf("%.1f ms", p.Avg)
			if rango != "1h" {
				d += fmt.Sprintf(" (máx %.1f)", p.Max)
			}
		}
		if p.Loss > 0 && p.Avg >= 0 {
			d += fmt.Sprintf(" · %.0f %% perdidos", p.Loss)
		}
		g.Puntos = append(g.Puntos, puntoDV{f1(X(float64(p.T)) - bw/2), f1(bw), time.Unix(p.T, 0).Format("02/01/2006 15:04") + " · " + d})
	}
	// resumen
	var suma, mx float64
	nok, lost, presente := 0, 0, false
	for _, p := range hist {
		if p.Avg > 0 {
			suma += p.Avg
			nok++
		}
		if p.Avg == 0 {
			presente = true
		}
		if p.Loss > 0 {
			lost++
		}
		mx = math.Max(mx, p.Max)
	}
	switch {
	case nok == 0 && presente:
		g.Info = "Presente: se le escucha en la red, pero no contesta las revisiones (no se puede medir su latencia)"
	default:
		per := "sin pérdidas"
		if lost > 0 {
			per = strconv.Itoa(lost) + " periodo(s) con pérdida"
		}
		prom := 0.0
		if nok > 0 {
			prom = suma / float64(nok)
		}
		g.Info = fmt.Sprintf("Promedio %.1f ms · máximo %.1f ms · %s", prom, mx, per)
	}
	return g
}

// ---------- edición ----------

type tipoOpDV struct {
	Clave, Nombre string
	Sel           bool
}

type edicionDV struct {
	ID, IP, MAC, Nombre, Ubicacion, Sugerido, Error string
	Tipos                                           []tipoOpDV
	Auto                                            bool
}

func edicionDe(d Device) edicionDV {
	e := edicionDV{ID: d.ID, IP: d.IP, MAC: d.MAC, Nombre: d.Name, Ubicacion: d.Location, Sugerido: d.Hostname, Auto: d.KindManual == ""}
	if e.Sugerido == "" {
		e.Sugerido = d.NetBIOS
	}
	for _, t := range tiposDV {
		e.Tipos = append(e.Tipos, tipoOpDV{t.Clave, t.Nombre, d.KindManual == t.Clave})
	}
	return e
}

type escanerDV struct{ Escaneando bool }

// ---------- rutas ----------

// lanzarEscaneo: las pruebas lo cambian para no barrer la red.
var lanzarEscaneo = func(m *Monitor) { go m.Scan() }

func rutasDispositivos(r chi.Router, store *Store, mon *Monitor) {
	csp := func(w http.ResponseWriter) { w.Header().Set("Content-Security-Policy", web.CSPEstricta) }
	puede := func(req *http.Request) bool {
		u := cuentas.Cuenta(req)
		return u != nil && (u.Role == "admin" || u.Role == "operador")
	}
	r.Get("/dispositivos", func(w http.ResponseWriter, req *http.Request) {
		v := req.URL.Query()
		q, f := recortar(v.Get("q"), 100), v.Get("f")
		if !filtrosDV[f] {
			f = ""
		}
		abiertos := map[string]bool{}
		for _, s := range v["abierto"] {
			abiertos[s] = true
		}
		dev := ""
		if x, ok := store.Device(v.Get("dev")); ok && !web.EsHTMX(req) {
			dev = x.ID
			abiertos[segOf(x.IP)] = true // el segmento del equipo se abre solo
		}
		d := armarDV(store, q, f, v.Get("seg"), abiertos, v.Has("demo"))
		csp(w)
		// al volver con "atrás", htmx pide la dirección con HX-Request: ahí hace falta la página entera
		if web.EsHTMX(req) && req.Header.Get("HX-History-Restore-Request") != "true" {
			web.Render(w, http.StatusOK, "dv-lista", d)
			return
		}
		u := cuentas.Cuenta(req)
		d.Marco = web.NuevoMarco("Dispositivos", "dispositivos", u.Name, u.Role)
		d.Puede = d.Marco.Puede
		d.Escaneando = mon.Scanning()
		d.AbrirDev = dev
		web.Render(w, http.StatusOK, "dispositivos", d)
	})
	r.Get("/dispositivos/segmento", func(w http.ResponseWriter, req *http.Request) {
		v := req.URL.Query()
		f := v.Get("f")
		if !filtrosDV[f] {
			f = ""
		}
		devs := store.Query(v.Get("seg"), recortar(v.Get("q"), 100), f, false, 1000)
		csp(w)
		web.Render(w, http.StatusOK, "dv-cuerpo", cuerpoDV{Filas: filasDe(devs, store.redSegmentos())})
	})
	r.Get("/dispositivos/equipo", func(w http.ResponseWriter, req *http.Request) {
		csp(w)
		d, ok := store.Device(req.URL.Query().Get("id"))
		if !ok {
			web.Render(w, http.StatusOK, "dv-no-existe", nil)
			return
		}
		web.Render(w, http.StatusOK, "dv-equipo", equipoDe(store, d, puede(req)))
	})
	r.Get("/dispositivos/grafica", func(w http.ResponseWriter, req *http.Request) {
		id := req.URL.Query().Get("id")
		if _, ok := store.Device(id); !ok {
			http.Error(w, "no existe el equipo", http.StatusNotFound)
			return
		}
		csp(w)
		web.Render(w, http.StatusOK, "dv-grafica", graficaDe(store, id, req.URL.Query().Get("r")))
	})
	r.Get("/dispositivos/editar", func(w http.ResponseWriter, req *http.Request) {
		if !puede(req) {
			http.Error(w, "tu perfil no permite este cambio", http.StatusForbidden)
			return
		}
		d, ok := store.Device(req.URL.Query().Get("id"))
		if !ok {
			http.Error(w, "no existe el equipo", http.StatusNotFound)
			return
		}
		csp(w)
		web.Render(w, http.StatusOK, "dv-editar", edicionDe(d))
	})
	r.Post("/dispositivos/equipo", func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		f := req.PostForm
		id := f.Get("id")
		d, ok := store.Device(id)
		if !ok {
			http.Error(w, "no existe el equipo", http.StatusNotFound)
			return
		}
		nombre, ubic := recortar(f.Get("nombre"), 120), recortar(f.Get("ubicacion"), 200)
		var tipo *string
		if f.Has("tipo") {
			t := f.Get("tipo")
			if t == "" {
				t = "auto"
			}
			tipo = &t
		}
		csp(w)
		if err := store.UpdateDevice(id, nombre, ubic, nombre != "", tipo); err != nil {
			e := edicionDe(d)
			e.Nombre, e.Ubicacion, e.Error = nombre, ubic, "Ese tipo de equipo no es válido."
			web.Render(w, http.StatusOK, "dv-editar", e)
			return
		}
		w.Header().Set("HX-Trigger", "dv-refrescar") // la lista se vuelve a pedir; la ventana se cierra
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/dispositivos/escanear", func(w http.ResponseWriter, req *http.Request) {
		esc := mon.Scanning()
		if !esc {
			w.Header().Set("HX-Trigger", "dv-refrescar") // terminó: la lista se actualiza
		}
		csp(w)
		web.Render(w, http.StatusOK, "dv-escaner", escanerDV{esc})
	})
	r.Post("/dispositivos/escanear", func(w http.ResponseWriter, req *http.Request) {
		lanzarEscaneo(mon)
		csp(w)
		web.Render(w, http.StatusOK, "dv-escaner", escanerDV{true})
	})
}

// panelRaiz sirve el panel viejo (Resumen); /?tab=dispositivos&dev=&ip= lleva a /dispositivos.
func panelRaiz(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	if q.Get("tab") == "dispositivos" {
		n := url.Values{}
		for _, k := range []string{"dev", "ip", "seg", "f", "q"} {
			if v := q.Get(k); v != "" {
				n.Set(k, v)
			}
		}
		dest := "/dispositivos"
		if len(n) > 0 {
			dest += "?" + n.Encode()
		}
		http.Redirect(w, req, dest, http.StatusSeeOther)
		return
	}
	web.Panel(w, req)
}
