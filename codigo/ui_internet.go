// ui_internet.go — Internet y servicios con Go + htmx.
//
//	GET    /internet                 página completa; con htmx, solo los datos (#in-datos)
//	POST   /internet/servicios       agregar un servicio (nombre, host, puerto) — Operador o más
//	DELETE /internet/servicios?id=   quitar un servicio — Operador o más
//
// Mismos datos que /api/outages y /api/targets (Store.Outages y Store.Targets), sin pasar por la
// API. #in-datos se vuelve a pedir solo cada 5 s. Los permisos los pone PuedeCambiar (los cambios
// piden Operador); Consulta tampoco ve los controles.
package main

import (
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
	"monitoreo/web"
)

type kpiCortes struct {
	Etiqueta string
	N        int
}

type filaCorte struct {
	Dia, Hora, Duracion, Causa string
	Sigue, NoSabe              bool
	Detalle                    string // por qué no se sabe la duración
}

// un día de la gráfica: Clase = altura (h0…h10) y si hubo cortes
type barraDia struct {
	Clase, Titulo string
}

type filaServicio struct {
	ID, Nombre, Destino, Punto, PuntoTitulo string
	Latencia                                string
	SinRespuesta, SinDatos                  bool
}

type datosInternet struct {
	Marco     web.Marco
	Puede     bool
	Mal       bool // sin internet ahora
	Estado    string
	Detalle   string
	Kpis      []kpiCortes
	Barras    []barraDia
	Desde     string // primer día de la gráfica
	Cortes    []filaCorte
	Servicios []filaServicio
	Aviso     string
	AvisoMal  bool
	ResetForm bool
}

var diasCorto = [...]string{"dom", "lun", "mar", "mié", "jue", "vie", "sáb"}
var diasLargo = [...]string{"domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"}
var mesesCorto = [...]string{"ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"}
var mesesLargo = [...]string{"enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"}

func inicioDia(t time.Time, atras int) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d-atras, 0, 0, 0, 0, t.Location())
}

// duracionTxt: "45 s", "3 min 20 s", "2 h 5 min".
func duracionTxt(seg int64) string {
	switch {
	case seg < 60:
		return fmt.Sprintf("%d s", seg)
	case seg < 3600:
		if seg%60 > 0 {
			return fmt.Sprintf("%d min %d s", seg/60, seg%60)
		}
		return fmt.Sprintf("%d min", seg/60)
	}
	return fmt.Sprintf("%d h %d min", seg/3600, seg%3600/60)
}

func duracionCorte(o Outage, ahora time.Time) int64 {
	fin := o.End
	if fin == 0 {
		fin = ahora.Unix()
	}
	if fin < o.Start {
		return 0
	}
	return fin - o.Start
}

func nombreDia(t, ahora time.Time) string {
	hoy := inicioDia(ahora, 0)
	switch {
	case !t.Before(hoy):
		return "Hoy"
	case !t.Before(hoy.AddDate(0, 0, -1)):
		return "Ayer"
	}
	return fmt.Sprintf("%s %d %s", diasCorto[t.Weekday()], t.Day(), mesesCorto[t.Month()-1])
}

func datosDeInternet(store *Store, puede bool, ahora time.Time) datosInternet {
	d := datosInternet{Puede: puede}
	cortes := store.Outages(30) // más recientes primero
	var actual *Outage
	for i := range cortes {
		if cortes[i].End == 0 {
			actual = &cortes[i]
			break
		}
	}
	// estado grande
	if actual != nil {
		d.Mal = true
		d.Estado = "Sin internet"
		d.Detalle = "desde las " + time.Unix(actual.Start, 0).In(ahora.Location()).Format("15:04") + " · " + duracionTxt(duracionCorte(*actual, ahora))
	} else {
		d.Estado = "Con internet"
		d.Detalle = "sin cortes registrados"
		if len(cortes) > 0 {
			d.Detalle = "último corte " + web.Hace(time.Unix(cortes[0].Start, 0))
		}
	}
	// contadores
	for _, k := range []struct {
		e string
		a int
	}{{"Hoy", 0}, {"7 días", 6}, {"30 días", 29}} {
		desde := inicioDia(ahora, k.a).Unix()
		n := 0
		for _, o := range cortes {
			if o.Start >= desde {
				n++
			}
		}
		d.Kpis = append(d.Kpis, kpiCortes{Etiqueta: k.e, N: n})
	}
	// barras: cortes por día, últimos 30 días
	var cuenta [30]int
	var secs [30]int64
	for _, o := range cortes {
		for i := 0; i < 30; i++ {
			t0 := inicioDia(ahora, 29-i)
			if o.Start >= t0.Unix() && o.Start < t0.AddDate(0, 0, 1).Unix() {
				cuenta[i]++
				secs[i] += duracionCorte(o, ahora)
				break
			}
		}
	}
	max := 1
	for _, n := range cuenta {
		if n > max {
			max = n
		}
	}
	for i := 0; i < 30; i++ {
		t0 := inicioDia(ahora, 29-i)
		dia := fmt.Sprintf("%s %d de %s", diasLargo[t0.Weekday()], t0.Day(), mesesLargo[t0.Month()-1])
		b := barraDia{Clase: "h0", Titulo: dia + ": sin cortes"}
		if n := cuenta[i]; n > 0 {
			b.Clase = "con h" + strconv.Itoa(int(math.Max(1, math.Round(float64(n)/float64(max)*10))))
			s := "cortes"
			if n == 1 {
				s = "corte"
			}
			b.Titulo = fmt.Sprintf("%s: %d %s · %s sin internet", dia, n, s, duracionTxt(secs[i]))
		}
		d.Barras = append(d.Barras, b)
	}
	p := inicioDia(ahora, 29)
	d.Desde = fmt.Sprintf("%d %s", p.Day(), mesesCorto[p.Month()-1])
	// tabla: los 30 últimos
	for i, o := range cortes {
		if i == 30 {
			break
		}
		ini := time.Unix(o.Start, 0).In(ahora.Location())
		f := filaCorte{Dia: nombreDia(ini, ahora), Hora: ini.Format("15:04")}
		switch {
		case o.End == 0:
			f.Sigue = true
		case o.End == o.Start && o.Note != "":
			f.NoSabe, f.Detalle = true, o.Note
		default:
			f.Hora += " – " + time.Unix(o.End, 0).In(ahora.Location()).Format("15:04")
			f.Duracion = duracionTxt(duracionCorte(o, ahora))
			f.Causa = o.Note
		}
		d.Cortes = append(d.Cortes, f)
	}
	// servicios
	for _, t := range store.Targets() {
		f := filaServicio{ID: t.ID, Nombre: t.Name, Destino: t.Host, PuntoTitulo: "Sin revisar todavía"}
		if t.Port > 0 {
			f.Destino += ":" + strconv.Itoa(t.Port)
		}
		switch {
		case t.LastCheck.IsZero() || t.LastCheck.Year() <= 1:
			f.SinDatos = true
		case t.Online:
			f.Punto, f.PuntoTitulo = "d-on", "Responde"
			if t.LatencyMs > 0 {
				f.Latencia = fmt.Sprintf("%.1f ms", t.LatencyMs)
			}
		default:
			f.Punto, f.PuntoTitulo, f.SinRespuesta = "d-off", "No responde", true
		}
		d.Servicios = append(d.Servicios, f)
	}
	return d
}

var hostValido = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// rutasInternet: "revisar" se llama (en segundo plano) al agregar un servicio para medirlo ya.
func rutasInternet(r chi.Router, store *Store, revisar func()) {
	r.Get("/internet", func(w http.ResponseWriter, req *http.Request) {
		u := cuentas.Cuenta(req)
		m := web.NuevoMarco("Internet y servicios", "internet", u.Name, u.Role)
		d := datosDeInternet(store, m.Puede, time.Now())
		w.Header().Set("Content-Security-Policy", web.CSPEstricta)
		// al volver con "atrás", htmx pide la dirección con HX-Request: ahí hace falta la página entera
		if web.EsHTMX(req) && req.Header.Get("HX-History-Restore-Request") != "true" {
			web.Render(w, http.StatusOK, "in-datos", d)
			return
		}
		d.Marco = m
		web.Render(w, http.StatusOK, "internet", d)
	})
	// los cambios solo llegan aquí con perfil Operador o más (PuedeCambiar)
	r.Post("/internet/servicios", func(w http.ResponseWriter, req *http.Request) {
		req.ParseForm()
		nombre, host := strings.TrimSpace(req.PostForm.Get("nombre")), strings.TrimSpace(req.PostForm.Get("host"))
		puerto, err := 0, ""
		if p := strings.TrimSpace(req.PostForm.Get("puerto")); p != "" {
			n, e := strconv.Atoi(p)
			if e != nil || n < 1 || n > 65535 {
				err = "El puerto debe ser un número del 1 al 65535 (vacío = ping)."
			}
			puerto = n
		}
		switch {
		case err != "":
		case host == "":
			err = "Escribe la IP o el dominio."
		case len(host) > 253 || !hostValido.MatchString(host):
			err = "La IP o el dominio no es válido."
		case len(nombre) > 60:
			err = "El nombre es muy largo (máximo 60)."
		}
		w.Header().Set("Content-Security-Policy", web.CSPEstricta)
		if err != "" {
			d := datosDeInternet(store, true, time.Now())
			d.Aviso, d.AvisoMal = err, true
			web.Render(w, http.StatusOK, "in-datos", d)
			return
		}
		if nombre == "" {
			nombre = host
		}
		store.AddTarget(Target{Name: nombre, Host: host, Port: puerto})
		if revisar != nil {
			go revisar()
		}
		d := datosDeInternet(store, true, time.Now())
		d.Aviso, d.ResetForm = "Servicio "+nombre+" agregado.", true
		web.Render(w, http.StatusOK, "in-datos", d)
	})
	r.Delete("/internet/servicios", func(w http.ResponseWriter, req *http.Request) {
		store.DeleteTarget(req.URL.Query().Get("id"))
		d := datosDeInternet(store, true, time.Now())
		d.Aviso = "Servicio quitado."
		w.Header().Set("Content-Security-Policy", web.CSPEstricta)
		web.Render(w, http.StatusOK, "in-datos", d)
	})
}
