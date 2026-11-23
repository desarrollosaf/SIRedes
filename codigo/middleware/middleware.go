// Package middleware: capas de seguridad que pasan TODAS las peticiones, en este
// orden (de afuera hacia adentro):
//
//	Recuperar        un error en una petición no tumba el servicio
//	Registro         deja en el diario los cambios y los errores (no cada consulta)
//	Cabeceras        cabeceras de seguridad (OWASP)
//	LimitarTamano    corta cuerpos de más de 64 KiB
//	LimitarIP        peticiones por segundo por IP (429 si se excede)
//	MismoOrigen      un cambio (POST, DELETE…) solo desde el propio panel (CSRF)
//
// Basado en el endurecimiento del backend de referencia (docs/hardening.md),
// adaptado a la Pi y sin dependencias externas.
package middleware

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Cadena aplica las capas en orden: la primera es la más externa.
func Cadena(h http.Handler, capas ...func(http.Handler) http.Handler) http.Handler {
	for i := len(capas) - 1; i >= 0; i-- {
		h = capas[i](h)
	}
	return h
}

// ---------- IP real ----------

// proxies en los que se confía para X-Real-IP / X-Forwarded-For
// (MONITOREO_PROXIES="ip1,ip2"). Sin ella esas cabeceras se ignoran: cualquiera
// puede escribirlas.
var proxies = func() map[string]bool {
	m := map[string]bool{}
	for _, ip := range strings.Split(os.Getenv("MONITOREO_PROXIES"), ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			m[ip] = true
		}
	}
	return m
}()

// IPReal: IP del cliente (la de conexión, salvo que venga de un proxy declarado).
func IPReal(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if !proxies[ip] {
		return ip
	}
	for _, h := range []string{"X-Real-Ip", "X-Forwarded-For"} {
		if v := r.Header.Get(h); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	return ip
}

func errorJSON(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---------- Recuperar ----------

func Recuperar(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				if err == http.ErrAbortHandler {
					panic(err)
				}
				log.Printf("[PÁNICO] %s %s: %v\n%s", r.Method, r.URL.Path, err, debug.Stack())
				errorJSON(w, http.StatusInternalServerError, "error interno; quedó en el registro")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ---------- Registro ----------

type conEstado struct {
	http.ResponseWriter
	status int
}

func (c *conEstado) WriteHeader(code int)        { c.status = code; c.ResponseWriter.WriteHeader(code) }
func (c *conEstado) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// Registro anota en el diario (journalctl) los cambios y las respuestas con
// error. Las consultas normales (cada 5 s por pantalla abierta) no, para no
// gastar la memoria SD.
func Registro(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		cw := &conEstado{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(cw, r)
		if r.Method != http.MethodGet && r.Method != http.MethodHead || cw.status >= 400 {
			log.Printf("http %s %s %d %s ip=%s", r.Method, r.URL.Path, cw.status, time.Since(t).Round(time.Millisecond), IPReal(r))
		}
	})
}

// ---------- Cabeceras ----------

// CSP: todo del mismo origen. 'unsafe-inline' en scripts y estilos solo mientras
// la interfaz tenga JavaScript y onclick en línea; se quita al pasar a htmx.
const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

func Cabeceras(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", csp)
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		if r.TLS != nil { // solo con HTTPS: en HTTP el navegador las ignora y avisa en la consola
			h.Set("Strict-Transport-Security", "max-age=31536000")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasSuffix(r.URL.Path, ".html") || r.URL.Path == "/" || r.URL.Path == "/login" {
			h.Set("Cache-Control", "no-store") // datos de la red y sesión: nada en cachés
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- Tamaño ----------

const maxCuerpo = 64 << 10 // la interfaz solo manda formularios chicos en JSON

func LimitarTamano(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxCuerpo)
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- Límite por IP ----------

// cubeta: token bucket simple (por IP).
type cubeta struct {
	fichas float64
	ult    time.Time
}

// LimitarIP: porSeg peticiones por segundo por IP con ráfaga de rafaga.
// Solo aplica a las rutas que empiecen con alguno de los prefijos ("" = todas).
func LimitarIP(porSeg float64, rafaga int, prefijos ...string) func(http.Handler) http.Handler {
	var mu sync.Mutex
	visitas := map[string]*cubeta{}
	go func() {
		for range time.Tick(time.Minute) {
			mu.Lock()
			for ip, c := range visitas {
				if time.Since(c.ult) > 3*time.Minute {
					delete(visitas, ip)
				}
			}
			mu.Unlock()
		}
	}()
	permite := func(ip string) bool {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		c := visitas[ip]
		if c == nil {
			c = &cubeta{fichas: float64(rafaga), ult: now}
			visitas[ip] = c
		}
		c.fichas += now.Sub(c.ult).Seconds() * porSeg
		if c.fichas > float64(rafaga) {
			c.fichas = float64(rafaga)
		}
		c.ult = now
		if c.fichas < 1 {
			return false
		}
		c.fichas--
		return true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			aplica := len(prefijos) == 0
			for _, p := range prefijos {
				aplica = aplica || strings.HasPrefix(r.URL.Path, p)
			}
			if aplica && !permite(IPReal(r)) {
				w.Header().Set("Retry-After", "2")
				errorJSON(w, http.StatusTooManyRequests, "demasiadas peticiones; espera un momento")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---------- Mismo origen (CSRF) ----------

// MismoOrigen: un cambio (cualquier método que no sea GET/HEAD/OPTIONS) solo se
// acepta si el navegador dice que viene de esta misma página. Así otra página
// abierta en el navegador no puede usar tu sesión para cambiar cosas.
// La API v1 (con token, sin cookie) no pasa por aquí.
func MismoOrigen(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet, r.Method == http.MethodHead, r.Method == http.MethodOptions,
			strings.HasPrefix(r.URL.Path, "/api/v1/"):
			next.ServeHTTP(w, r)
			return
		}
		if !mismoOrigen(r) {
			errorJSON(w, http.StatusForbidden, "cambio rechazado: no viene del panel")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func mismoOrigen(r *http.Request) bool {
	// navegadores actuales: Sec-Fetch-Site lo pone el navegador y la página no puede falsearlo
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "cross-site", "same-site":
		return false
	}
	// navegadores viejos: Origin, y si no, Referer
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return false
	}
	u, err := url.Parse(src)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}
