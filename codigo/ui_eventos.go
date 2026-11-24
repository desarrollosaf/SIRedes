// ui_eventos.go — Eventos con Go + htmx.
//
//	GET /eventos?seg=&tipo=&q=&dias=   página completa; con htmx, solo la lista (#ev-lista)
//
// Mismos filtros que tenía el panel viejo (/api/events?filtro=1): segmento ("-" = generales),
// tipo (imp, con, new, info), texto y días. Consulta SQLite (DB.QueryEvents, máx. 500).
package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
	"monitoreo/web"
)

const maxEventos = 500

type filtrosEv struct {
	Seg, Tipo, Q, Dias string
}

type filaEvento struct {
	Cuando, Clase, Nombre, Mensaje string
}

type datosEventos struct {
	Marco     web.Marco
	F         filtrosEv
	Segmentos []opcionSeg
	Filas     []filaEvento
	Cuenta    string
}

var tiposEvento = map[string][]string{
	"imp":  {"offline", "corte", "online"},
	"con":  {"conectado", "desconectado"},
	"new":  {"new"},
	"info": {"info"},
}

var nombreEvento = map[string]string{
	"new": "Nuevo", "offline": "Caída", "corte": "Corte", "online": "Volvió",
	"desconectado": "Desconectado", "conectado": "Conectado", "info": "Info",
}

// desdeDias: "1" = hoy (desde la medianoche); 7, 30 o 365 = esos días atrás.
func desdeDias(dias string, ahora time.Time) (string, int64) {
	switch dias {
	case "1":
		y, m, d := ahora.Date()
		return "1", time.Date(y, m, d, 0, 0, 0, 0, ahora.Location()).Unix()
	case "30", "365":
	default:
		dias = "7"
	}
	n := 7
	if dias == "30" {
		n = 30
	} else if dias == "365" {
		n = 365
	}
	return dias, ahora.AddDate(0, 0, -n).Unix()
}

func datosDeEventos(store *Store, f filtrosEv) datosEventos {
	f.Q = strings.TrimSpace(f.Q)
	if f.Seg != "-" && f.Seg != "" {
		f.Seg = segKey(f.Seg)
	}
	if _, ok := tiposEvento[f.Tipo]; !ok {
		f.Tipo = ""
	}
	dias, desde := desdeDias(f.Dias, time.Now())
	f.Dias = dias
	d := datosEventos{F: f}
	keys, vistos, _ := listaSegs(store)
	for _, k := range keys {
		d.Segmentos = append(d.Segmentos, opcionSeg{Seg: k, Etiqueta: etiquetaSeg(k), Equipos: vistos[k]})
	}
	if store.db != nil {
		for _, e := range store.db.QueryEvents(f.Seg, tiposEvento[f.Tipo], f.Q, desde, maxEventos) {
			n := nombreEvento[e.Kind]
			if n == "" {
				n = e.Kind
			}
			d.Filas = append(d.Filas, filaEvento{Cuando: e.Time.Format("02/01/06 15:04:05"), Clase: e.Kind, Nombre: n, Mensaje: e.Message})
		}
	}
	switch n := len(d.Filas); {
	case n >= maxEventos:
		d.Cuenta = "Los 500 más recientes"
	case n == 1:
		d.Cuenta = "1 evento"
	default:
		d.Cuenta = strconv.Itoa(n) + " eventos"
	}
	return d
}

func rutasEventos(r chi.Router, store *Store) {
	r.Get("/eventos", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		d := datosDeEventos(store, filtrosEv{Seg: q.Get("seg"), Tipo: q.Get("tipo"), Q: q.Get("q"), Dias: q.Get("dias")})
		w.Header().Set("Content-Security-Policy", web.CSPEstricta)
		// al volver con "atrás", htmx pide la dirección con HX-Request: ahí hace falta la página entera
		if web.EsHTMX(req) && req.Header.Get("HX-History-Restore-Request") != "true" {
			web.Render(w, http.StatusOK, "ev-lista", d)
			return
		}
		u := cuentas.Cuenta(req)
		d.Marco = web.NuevoMarco("Eventos", "eventos", u.Name, u.Role)
		web.Render(w, http.StatusOK, "eventos", d)
	})
}
