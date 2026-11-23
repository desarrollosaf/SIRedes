// ui_config.go — Configuración con Go + htmx: página y pestañas Segmentos y Equipos.
// (Usuarios está en app/cuentas/ui.go.) Cuando se migren Dispositivos y el resto,
// esto pasa a app/red/.
//
//	GET    /configuracion?tab=…&seg=…      página completa
//	GET    /configuracion/{tab}            solo el cuerpo (htmx; cambia #cfg)
//	GET    /configuracion/segmentos/nuevo | /editar?seg=   ventana
//	POST   /configuracion/segmentos        guardar
//	DELETE /configuracion/segmentos?seg=   quitar (solo los agregados a mano)
//	POST   /configuracion/equipos          guardar nombre y ubicación de un equipo (fila)
package main

import (
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
	"monitoreo/web"
)

type filaSeg struct {
	Seg, Nombre, Ubicacion, Puerta string
	Equipos                        int
	Oculto                         bool
}

type datosSegs struct {
	Filas []filaSeg
	Puede bool
	Aviso string
}

type opcionSeg struct {
	Seg, Etiqueta string
	Equipos       int
}

type filaEquipo struct {
	ID, IP, MAC, Nombre, Ubicacion, Fabricante, Sugerido string
	Puede, Guardado                                      bool
}

type datosEquipos struct {
	Seg       string
	Segmentos []opcionSeg
	Filas     []filaEquipo
	Puede     bool
}

type ventanaSeg struct {
	Nuevo                                                bool
	Seg, Nombre, Ubicacion, Puerta, PuertaEjemplo, Error string
	Oculto, Manual                                       bool
}

type datosConfig struct {
	Marco     web.Marco
	Tab       string
	Usuarios  cuentas.DatosUsuarios
	Segmentos datosSegs
	Equipos   datosEquipos
}

// orden natural: 1, 2, 10, 100, 10.20.30, 172.16.5
func segMenor(a, b string) bool {
	na, ea := strconv.Atoi(a)
	nb, eb := strconv.Atoi(b)
	switch {
	case ea == nil && eb == nil:
		return na < nb
	case ea == nil:
		return true
	case eb == nil:
		return false
	}
	ia, ib := net.ParseIP(a+".0").To4(), net.ParseIP(b+".0").To4()
	if ia != nil && ib != nil {
		for i := range ia {
			if ia[i] != ib[i] {
				return ia[i] < ib[i]
			}
		}
	}
	return a < b
}

// cuántos equipos tiene cada segmento (sin contar otras IPs del mismo aparato)
func equiposPorSeg(store *Store) map[string]int {
	n := map[string]int{}
	for _, d := range store.DeviceList() {
		if !d.Alias {
			n[segOf(d.IP)]++
		}
	}
	return n
}

// todos los segmentos: vistos en la red + configurados a mano
func listaSegs(store *Store) ([]string, map[string]int, map[string]SegCfg) {
	vistos := equiposPorSeg(store)
	cfg := map[string]SegCfg{}
	for _, c := range SegConfigList() {
		cfg[c.Seg] = c
	}
	set := map[string]bool{}
	for k := range vistos {
		set[k] = true
	}
	for k := range cfg {
		set[k] = true
	}
	delete(set, "169.254")
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return segMenor(keys[i], keys[j]) })
	return keys, vistos, cfg
}

// puerta detectada que funciona (la de /api/segments)
func puertasDetectadas(store *Store) map[string]string {
	m := map[string]string{}
	for _, g := range store.Segments() {
		m[g.Seg] = g.Gateway
	}
	return m
}

func datosSegmentos(store *Store, puede bool, aviso string) datosSegs {
	keys, vistos, cfg := listaSegs(store)
	gw := puertasDetectadas(store)
	d := datosSegs{Puede: puede, Aviso: aviso}
	for _, k := range keys {
		c := cfg[k]
		p := c.Gateway
		if p == "" {
			p = gw[k]
		}
		d.Filas = append(d.Filas, filaSeg{Seg: k, Nombre: c.Name, Ubicacion: c.Location, Puerta: p, Equipos: vistos[k], Oculto: c.Hidden})
	}
	return d
}

func etiquetaSeg(k string) string {
	if n := segName(k); n != "" {
		return n + " (" + k + ")"
	}
	return "Segmento " + k
}

func datosDeEquipos(store *Store, seg string, puede bool) datosEquipos {
	keys, vistos, _ := listaSegs(store)
	if seg == "" || vistos[seg] == 0 && segName(seg) == "" {
		for _, k := range keys { // el primero con equipos
			if vistos[k] > 0 {
				seg = k
				break
			}
		}
	}
	d := datosEquipos{Seg: seg, Puede: puede}
	for _, k := range keys {
		d.Segmentos = append(d.Segmentos, opcionSeg{Seg: k, Etiqueta: etiquetaSeg(k), Equipos: vistos[k]})
	}
	devs := store.Devices(seg, false)
	sort.Slice(devs, func(i, j int) bool { return ipNum(devs[i].IP) < ipNum(devs[j].IP) })
	for _, x := range devs {
		if x.Alias {
			continue
		}
		d.Filas = append(d.Filas, filaDeEquipo(x, puede))
	}
	return d
}

func filaDeEquipo(x Device, puede bool) filaEquipo {
	sug := x.Hostname
	if sug == "" {
		sug = x.NetBIOS
	}
	return filaEquipo{ID: x.ID, IP: x.IP, MAC: x.MAC, Nombre: x.Name, Ubicacion: x.Location, Fabricante: x.Vendor, Sugerido: sug, Puede: puede}
}

func ipNum(ip string) uint32 {
	v := net.ParseIP(ip).To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func rutasConfig(r chi.Router, store *Store, mon *Monitor, auth *cuentas.Auth) {
	armar := func(req *http.Request, tab, seg, aviso string) datosConfig {
		u := cuentas.Cuenta(req)
		m := web.NuevoMarco("Configuración", "configuracion", u.Name, u.Role)
		if tab != "usuarios" && tab != "equipos" {
			tab = "segmentos"
		}
		if tab == "usuarios" && !m.Admin {
			tab = "segmentos"
		}
		d := datosConfig{Marco: m, Tab: tab}
		switch tab {
		case "usuarios":
			d.Usuarios = auth.DatosUsuarios(u.Name, aviso)
		case "equipos":
			d.Equipos = datosDeEquipos(store, segKey(seg), m.Puede)
		default:
			d.Segmentos = datosSegmentos(store, m.Puede, aviso)
		}
		return d
	}
	r.Get("/configuracion", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		w.Header().Set("Content-Security-Policy", web.CSPEstricta)
		web.Render(w, http.StatusOK, "configuracion", armar(req, q.Get("tab"), q.Get("seg"), ""))
	})
	r.Get("/configuracion/{tab:usuarios|segmentos|equipos}", func(w http.ResponseWriter, req *http.Request) {
		tab, seg := chi.URLParam(req, "tab"), req.URL.Query().Get("seg")
		if !web.EsHTMX(req) { // dirección escrita a mano: la página entera
			u := "/configuracion?tab=" + tab
			if seg != "" {
				u += "&seg=" + seg
			}
			http.Redirect(w, req, u, http.StatusSeeOther)
			return
		}
		web.Render(w, http.StatusOK, "cfg-cuerpo", armar(req, tab, seg, ""))
	})

	// --- segmentos ---
	ventana := func(k string) ventanaSeg {
		v := ventanaSeg{Seg: k}
		for _, c := range SegConfigList() {
			if c.Seg == k {
				v.Nombre, v.Ubicacion, v.Puerta, v.Oculto, v.Manual = c.Name, c.Location, c.Gateway, c.Hidden, c.Manual
			}
		}
		if v.Puerta == "" {
			v.Puerta = puertasDetectadas(store)[k] // la que funciona ya viene escrita
		}
		if _, err := strconv.Atoi(k); err == nil {
			v.PuertaEjemplo = "192.168." + k + ".254"
		}
		return v
	}
	r.Get("/configuracion/segmentos/nuevo", func(w http.ResponseWriter, req *http.Request) {
		web.Render(w, http.StatusOK, "cfg-segmento-ventana", ventanaSeg{Nuevo: true})
	})
	r.Get("/configuracion/segmentos/editar", func(w http.ResponseWriter, req *http.Request) {
		web.Render(w, http.StatusOK, "cfg-segmento-ventana", ventana(segKey(req.URL.Query().Get("seg"))))
	})
	r.Post("/configuracion/segmentos", func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		f := req.PostForm
		nuevo := f.Get("nuevo") == "1"
		k := segKey(f.Get("seg"))
		var old SegCfg
		for _, c := range SegConfigList() {
			if c.Seg == k {
				old = c
			}
		}
		// la puerta detectada que funciona no se fija a mano (sigue automática); otra IP sí
		puerta, det := strings.TrimSpace(f.Get("puerta")), puertasDetectadas(store)[k]
		fija := ""
		if puerta != "" && (puerta != det || old.Gateway != "") {
			fija = puerta
		}
		c := SegCfg{Seg: f.Get("seg"), Name: f.Get("nombre"), Location: f.Get("ubicacion"), Gateway: fija,
			Manual: nuevo || old.Manual, Hidden: !nuevo && f.Get("oculto") == "1"}
		if err := store.SetSegCfg(c); err != nil {
			v := ventanaSeg{Nuevo: nuevo, Seg: f.Get("seg"), Nombre: c.Name, Ubicacion: c.Location, Puerta: puerta,
				Oculto: c.Hidden, Manual: old.Manual, Error: err.Error()}
			w.Header().Set("HX-Retarget", "#modal")
			w.Header().Set("HX-Reswap", "innerHTML")
			web.Render(w, http.StatusOK, "cfg-segmento-ventana", v)
			return
		}
		aviso := "Segmento " + k + " guardado."
		if nuevo {
			aviso = "Segmento " + k + " agregado; se está barriendo."
			go mon.Scan()
		}
		web.Render(w, http.StatusOK, "cfg-segmentos-y-cerrar", datosSegmentos(store, true, aviso))
	})
	r.Delete("/configuracion/segmentos", func(w http.ResponseWriter, req *http.Request) {
		k := segKey(req.URL.Query().Get("seg"))
		store.DeleteSegCfg(k)
		web.Render(w, http.StatusOK, "cfg-segmentos-y-cerrar", datosSegmentos(store, true, "Segmento "+k+" quitado."))
	})

	// --- equipos: guarda una fila y la devuelve marcada como guardada ---
	r.Post("/configuracion/equipos", func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		f := req.PostForm
		id := f.Get("id")
		if _, ok := store.Device(id); !ok {
			http.Error(w, "no existe el equipo", 404)
			return
		}
		nombre, ubic := strings.TrimSpace(f.Get("nombre")), strings.TrimSpace(f.Get("ubicacion"))
		store.UpdateDevice(id, nombre, ubic, nombre != "")
		d, _ := store.Device(id)
		fila := filaDeEquipo(d, true)
		fila.Guardado = true
		web.Render(w, http.StatusOK, "cfg-equipo-fila", fila)
	})
}
