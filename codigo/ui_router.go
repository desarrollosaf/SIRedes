// ui_router.go — Router (SNMP) con Go + htmx.
//
//	GET /router                        página completa; con htmx, solo los datos (#rt-datos)
//	GET /router/segmento?red=&puerta=  ventana con los equipos de un segmento (ARP del router)
//
// Mismos datos que /api/snmp y /api/snmp/equipos (SNMPStatus, SNMPARPIn), sin pasar por la API.
// Los datos se refrescan solos cada 5 s (hx-trigger="every 5s"). Si SNMP no está activo,
// la pantalla solo muestra un aviso.
package main

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
	"monitoreo/web"
)

type segRouter struct {
	Red, Gw, Puerta, Equipos string
}

type cableRouter struct {
	Nombre, Alias       string
	Estado, EstadoClase string // texto y color del estado
	Icono               string // i-ok, i-bad, i-gray
	Apagado, ConDatos   bool
	Equipos             int
	Bajada, Subida      string
	Errores, ErrClase   string
	ErrAcum             string
	ConPct              bool
	Pct                 int
	Segs                []segRouter
}

type internetRouter struct {
	Hay, Rapida         bool
	Cable               cableRouter
	Bajada, Subida      string
	Errores, ErrClase   string
	Estado, EstadoClase string // línea de estado por tráfico (cada 5 s)
	Desde, Motivo       string
	Linea               string
}

type datosRouter struct {
	Marco   web.Marco
	Activo  bool
	Mal     bool
	Nombre  string
	IP      string
	Detalle string
	Inet    internetRouter
	Cables  []cableRouter
}

type filaARP struct {
	IP, MAC, Nombre, Fab, ID string
}

type ventanaRouterSeg struct {
	Red, Puerta string
	Filas       []filaARP
	Cuenta      string
}

func mbpsTxt(v float64) string {
	if v >= 100 {
		return fmt.Sprintf("%d Mb/s", int(math.Round(v)))
	}
	return fmt.Sprintf("%.1f Mb/s", v)
}

func velTxt(v float64) string {
	switch {
	case v <= 0:
		return "—"
	case v >= 1000:
		return strconv.FormatFloat(v/1000, 'f', -1, 64) + " Gb/s"
	}
	return strconv.FormatFloat(v, 'f', -1, 64) + " Mb/s"
}

func milesTxt(n uint64) string {
	s := strconv.FormatUint(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func encendidoTxt(seg int64) string {
	switch {
	case seg <= 0:
		return ""
	case seg >= 86400:
		return fmt.Sprintf("%d días", seg/86400)
	}
	return fmt.Sprintf("%d h %d min", seg/3600, seg%3600/60)
}

func erroresTxt(f SNMPIface) (txt, clase string) {
	switch {
	case !f.ErrActive:
		return "0", ""
	case f.Errors > 0:
		return strconv.FormatUint(f.Errors, 10) + " en 30 s", "c-warn"
	}
	return "en los últimos 10 min", "c-warn"
}

func segsRouter(f SNMPIface) []segRouter {
	var out []segRouter
	for _, g := range f.Segmentos {
		p := "ruta directa"
		if g.Router != "" {
			p = "puerta " + g.Router
		}
		n := strconv.Itoa(g.Equipos) + " equipos"
		if g.Equipos == 1 {
			n = "1 equipo"
		}
		out = append(out, segRouter{Red: g.Red, Gw: g.Router, Puerta: p, Equipos: n})
	}
	return out
}

func cableDe(f SNMPIface, ok bool) cableRouter {
	c := cableRouter{Nombre: f.Name, Equipos: f.Equipos, ConDatos: ok, Segs: segsRouter(f), Apagado: !f.Up}
	if f.Alias != "" && f.Alias != f.Name {
		c.Alias = f.Alias
	}
	switch {
	case f.Up:
		c.Estado, c.EstadoClase, c.Icono = "● arriba · "+velTxt(f.SpeedMbps), "c-ok", "i-ok"
	case f.Fell:
		c.Estado, c.EstadoClase, c.Icono = "● caída", "c-bad", "i-bad"
	default:
		c.Estado, c.Icono = "● sin cable", "i-gray"
	}
	c.Errores, c.ErrClase = erroresTxt(f)
	if f.ErrorTotal > 0 {
		c.ErrAcum = milesTxt(f.ErrorTotal) + " acumulados"
	}
	return c
}

func datosDeRouter(s SNMPState) datosRouter {
	d := datosRouter{Activo: s.Active}
	if !s.Active {
		return d
	}
	d.Mal = s.Down
	d.Nombre = s.Name
	if s.SysName != "" {
		d.Nombre += " · " + s.SysName
	}
	d.IP = s.IP
	switch {
	case s.Down:
		d.Detalle = "no responde por SNMP"
	case s.Error != "":
		d.Detalle = s.Error
	default:
		descr := []rune(s.SysDescr)
		if len(descr) > 60 {
			descr = descr[:60]
		}
		d.Detalle = string(descr)
		if up := encendidoTxt(s.Uptime); up != "" {
			d.Detalle += " · encendido " + up
		}
	}
	ok := !s.Down && s.Last != nil
	var ifs []SNMPIface
	for _, f := range s.Ifaces {
		if f.AdminUp {
			ifs = append(ifs, f)
		}
	}
	var wan *SNMPIface
	for i := range ifs {
		if ifs[i].Internet {
			wan = &ifs[i]
			break
		}
	}
	x := s.Inet
	if wan != nil {
		in := internetRouter{Hay: true, Rapida: x.Rapida && !s.Down, Cable: cableDe(*wan, ok)}
		in.Errores, in.ErrClase = erroresTxt(*wan)
		bajada, subida := wan.InMbps, wan.OutMbps
		if x.Rapida {
			bajada, subida = x.Bajada, x.Subida
		}
		in.Bajada, in.Subida = "↓ "+mbpsTxt(bajada), "↑ "+mbpsTxt(subida)
		if !ok {
			in.Bajada, in.Subida, in.Errores, in.ErrClase = "–", "–", "–", ""
		}
		if in.Rapida {
			switch x.Estado {
			case "ok":
				in.Estado, in.EstadoClase = "Con internet", "c-ok"
			case "sospecha":
				in.Estado, in.EstadoClase = "Revisando: casi no regresa tráfico de internet", "c-warn"
			case "sin":
				in.Estado, in.EstadoClase = "Sin internet", "c-bad"
			case "cable":
				in.Estado, in.EstadoClase = "Sin internet: puerto de internet abajo", "c-bad"
			default:
				in.Estado, in.EstadoClase = "Midiendo…", "c-mut"
			}
			if x.Desde != nil && x.Estado != "ok" {
				in.Desde = "desde " + x.Desde.Format("15:04")
			}
			in.Motivo = x.Motivo
			in.Linea = "Cada 5 s: equipos → router " + mbpsTxt(x.Local) + " · regresa de internet " + mbpsTxt(x.Bajada)
			if !x.Horario {
				in.Linea += " · fuera de horario solo se vigila el puerto"
			}
		}
		d.Inet = in
	}
	tot := 0.0
	if wan != nil {
		tot = wan.InMbps
	}
	for _, f := range ifs {
		if wan != nil && f.Index == wan.Index {
			continue
		}
		if len(f.Segmentos) == 0 && f.Equipos == 0 && f.SpeedMbps == 0 {
			continue // interfaces internas del router
		}
		c := cableDe(f, ok)
		// lo que el router manda por el cable es lo que bajan sus equipos; lo que recibe, lo que suben
		c.Bajada, c.Subida = "↓ "+mbpsTxt(f.OutMbps), "↑ "+mbpsTxt(f.InMbps)
		if !ok {
			c.Bajada, c.Subida, c.Errores, c.ErrClase = "–", "–", "–", ""
		}
		if f.Up && tot > 0 {
			c.ConPct, c.Pct = true, int(math.Min(100, math.Round(f.OutMbps/tot*100)))
		}
		d.Cables = append(d.Cables, c)
	}
	return d
}

// equipos de un segmento según el ARP del router, con nombre y fabricante si la Pi los conoce
func filasARP(store *Store, red string) []filaARP {
	arp := SNMPARPIn(red)
	byIP := map[string]Device{}
	if len(arp) > 0 {
		for _, d := range store.DeviceList() {
			if d.Alias {
				continue
			}
			if o, ok := byIP[d.IP]; !ok || (!o.Online && d.Online) {
				byIP[d.IP] = d
			}
		}
	}
	out := make([]filaARP, 0, len(arp))
	for _, a := range arp {
		x := filaARP{IP: a.IP, MAC: a.MAC, Fab: vendorOf(a.MAC)}
		if d, ok := byIP[a.IP]; ok && strings.EqualFold(d.MAC, a.MAC) {
			x.ID = d.ID
			x.Nombre = d.Name
			for _, n := range []string{d.Hostname, d.NetBIOS, d.MDNS} {
				if x.Nombre == "" {
					x.Nombre = n
				}
			}
			if d.Vendor != "" {
				x.Fab = d.Vendor
			}
		}
		out = append(out, x)
	}
	return out
}

func rutasRouter(r chi.Router, store *Store) {
	r.Get("/router", func(w http.ResponseWriter, req *http.Request) {
		d := datosDeRouter(SNMPStatus())
		w.Header().Set("Content-Security-Policy", web.CSPEstricta)
		// al volver con "atrás", htmx pide la dirección con HX-Request: ahí hace falta la página entera
		if web.EsHTMX(req) && req.Header.Get("HX-History-Restore-Request") != "true" {
			web.Render(w, http.StatusOK, "rt-datos", d)
			return
		}
		u := cuentas.Cuenta(req)
		d.Marco = web.NuevoMarco("Router", "router", u.Name, u.Role)
		web.Render(w, http.StatusOK, "router", d)
	})
	r.Get("/router/segmento", func(w http.ResponseWriter, req *http.Request) {
		red := req.URL.Query().Get("red")
		if _, _, err := net.ParseCIDR(red); err != nil {
			http.Error(w, "segmento no válido", http.StatusBadRequest)
			return
		}
		v := ventanaRouterSeg{Red: red, Puerta: "ruta directa", Filas: filasARP(store, red)}
		if gw := net.ParseIP(req.URL.Query().Get("puerta")); gw != nil {
			v.Puerta = "puerta " + gw.String()
		}
		if n := len(v.Filas); n == 1 {
			v.Cuenta = "1 equipo en la tabla ARP del router"
		} else {
			v.Cuenta = strconv.Itoa(n) + " equipos en la tabla ARP del router"
		}
		w.Header().Set("Content-Security-Policy", web.CSPEstricta)
		web.Render(w, http.StatusOK, "rt-segmento", v)
	})
}
