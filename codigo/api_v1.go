package main

// API v1 para sistemas externos (p. ej. un front en React que genera alertas y tickets).
// - Solo funciona si hay token: MONITOREO_TOKEN (en /etc/monitoreo/api.conf, lo crea install.sh).
// - El token va en el encabezado  Authorization: Bearer <token>  (o X-Token: <token>).
// - CORS: MONITOREO_CORS = orígenes permitidos separados por coma (ej. https://panel.midominio.com)
//   o "*" para cualquiera. Vacío = no se permite llamar desde navegador en otro dominio.
// La interfaz propia de la Pi sigue usando /api/... como siempre.

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type apiV1 struct {
	token   string
	origins []string
	store   *Store
	mon     *Monitor
}

func newAPIv1(store *Store, mon *Monitor, token, cors string) *apiV1 {
	a := &apiV1{token: strings.TrimSpace(token), store: store, mon: mon}
	for _, o := range strings.Split(cors, ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			a.origins = append(a.origins, o)
		}
	}
	return a
}

func (a *apiV1) originOK(o string) bool {
	for _, x := range a.origins {
		if x == "*" || strings.EqualFold(x, o) {
			return true
		}
	}
	return false
}

func (a *apiV1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && a.originOK(o) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", o)
		h.Set("Access-Control-Allow-Headers", "Authorization, X-Token, Content-Type")
		h.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		h.Set("Access-Control-Max-Age", "600")
		h.Add("Vary", "Origin")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if a.token == "" {
		http.Error(w, "API v1 desactivada: falta MONITOREO_TOKEN", http.StatusServiceUnavailable)
		return
	}
	got := r.Header.Get("X-Token")
	if b := r.Header.Get("Authorization"); strings.HasPrefix(b, "Bearer ") {
		got = strings.TrimPrefix(b, "Bearer ")
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
		http.Error(w, "no autorizado", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "solo lectura (GET)", http.StatusMethodNotAllowed)
		return
	}
	switch strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/"), "/") {
	case "estado":
		writeJSON(w, a.estado())
	case "segmentos":
		writeJSON(w, a.store.Segments())
	case "eventos":
		writeJSON(w, a.eventos(r))
	case "cortes":
		days, _ := strconv.Atoi(r.URL.Query().Get("dias"))
		if days <= 0 || days > 366 {
			days = 30
		}
		out := a.store.Outages(days)
		if out == nil {
			out = []Outage{}
		}
		writeJSON(w, out)
	case "router":
		writeJSON(w, SNMPStatus())
	default:
		http.Error(w, "no existe; usa estado, segmentos, eventos, cortes o router", http.StatusNotFound)
	}
}

type v1SegAlerta struct {
	Seg        string `json:"seg"`
	Nombre     string `json:"nombre,omitempty"`
	Puerta     string `json:"puerta,omitempty"`
	Desde      int64  `json:"desde,omitempty"` // unix; 0 = no se sabe
	Conectados int    `json:"conectados"`
}

type v1Estado struct {
	Version  string `json:"version"`
	Hora     int64  `json:"hora"` // unix de la Pi
	Internet struct {
		Estado string `json:"estado"`          // ok | sin | revisando
		Desde  int64  `json:"desde,omitempty"` // unix: inicio del corte en curso
	} `json:"internet"`
	SegmentosSinInternet []v1SegAlerta `json:"segmentosSinInternet"`
	Resumen              struct {
		Segmentos   int `json:"segmentos"`
		ConInternet int `json:"conInternet"`
		SinInternet int `json:"sinInternet"`
		NoSeSabe    int `json:"noSeSabe"`
		Equipos     int `json:"equipos"`
		Conectados  int `json:"conectados"`
	} `json:"resumen"`
}

// estado: todo lo necesario para decidir una alerta "sin internet" en una sola llamada.
func (a *apiV1) estado() v1Estado {
	var e v1Estado
	e.Version, e.Hora = version, time.Now().Unix()

	a.store.mu.RLock()
	down, init := a.store.inetDown, a.store.inetInit || a.store.db == nil
	a.store.mu.RUnlock()
	switch {
	case down != 0:
		e.Internet.Estado, e.Internet.Desde = "sin", down
	case !init:
		e.Internet.Estado = "revisando"
	default:
		e.Internet.Estado = "ok"
	}

	e.SegmentosSinInternet = []v1SegAlerta{}
	for _, s := range a.store.Segments() {
		e.Resumen.Segmentos++
		e.Resumen.Equipos += s.Total
		e.Resumen.Conectados += s.Present
		switch s.Net {
		case "ok":
			e.Resumen.ConInternet++
		case "sin":
			e.Resumen.SinInternet++
			al := v1SegAlerta{Seg: s.Seg, Nombre: s.Name, Puerta: s.Gateway, Conectados: s.Online}
			if !s.NetSince.IsZero() {
				al.Desde = s.NetSince.Unix()
			}
			e.SegmentosSinInternet = append(e.SegmentosSinInternet, al)
		default:
			e.Resumen.NoSeSabe++
		}
	}
	return e
}

type v1Evento struct {
	Hora    int64  `json:"hora"`
	Tipo    string `json:"tipo"`
	Mensaje string `json:"mensaje"`
	Seg     string `json:"seg,omitempty"`
}

// eventos?desde=<unix> : eventos posteriores a esa hora (más viejos primero),
// para que el front pregunte cada X segundos solo por lo nuevo.
func (a *apiV1) eventos(r *http.Request) []v1Evento {
	since, _ := strconv.ParseInt(r.URL.Query().Get("desde"), 10, 64)
	all := a.store.Events() // más recientes primero
	out := []v1Evento{}
	for i := len(all) - 1; i >= 0; i-- {
		ev := all[i]
		if ev.Time.Unix() <= since {
			continue
		}
		out = append(out, v1Evento{Hora: ev.Time.Unix(), Tipo: ev.Kind, Mensaje: ev.Message, Seg: ev.Seg})
	}
	return out
}
