// servidor.go — rutas HTTP con chi y capas de seguridad.
//
//	todas            Recuperar, Registro, Cabeceras, Tamaño, Límite por IP, Mismo origen (CSRF), gzip
//	/api/v1/*        API para otros sistemas (su propio token)
//	públicas         /login, /api/auth/* (con límite más estricto), /static/* y el panel (sin datos)
//	con sesión       /api/* — consultar: cualquier perfil; cambiar: Operador o Administrador
//	solo admin       /api/usuarios, /api/seguridad
package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
	"monitoreo/middleware"
	"monitoreo/web"
)

// rutas arma el enrutador completo.
func rutas(store *Store, mon *Monitor, auth *cuentas.Auth, v1 http.Handler) http.Handler {
	r := chi.NewRouter()
	r.Use(
		middleware.Recuperar,
		middleware.Registro,
		middleware.Cabeceras,
		middleware.LimitarTamano,
		middleware.LimitarIP(30, 120), // 30/s por IP, ráfaga 120 ("Abrir todos" pide ~60 segmentos)
		middleware.MismoOrigen,        // cambios solo desde el propio panel (la API v1 no pasa por aquí)
		withGzip,
	)

	// API para otros sistemas: token propio, sin cookie
	r.Handle("/api/v1/*", v1)

	// públicas
	r.Group(func(r chi.Router) {
		r.Use(middleware.LimitarIP(2, 10)) // entrar y cambiar claves: más estricto
		auth.RutasPublicas(r)              // /login (Go + htmx) y /api/auth/*
	})
	r.Handle("/static/*", web.Static())

	// con sesión
	r.Group(func(r chi.Router) {
		r.Use(auth.Sesion)
		auth.RutasCuenta(r) // cambiar mi contraseña: cualquier perfil
		r.Group(func(r chi.Router) {
			r.Use(cuentas.PuedeCambiar)
			registerAPI(r, store, mon)
			rutasConfig(r, store, mon, auth)          // Configuración (Go + htmx)
			rutasEventos(r, store)                    // Eventos (Go + htmx)
			rutasDispositivos(r, store, mon)          // Dispositivos (Go + htmx)
			rutasRouter(r, store)                     // Router SNMP (Go + htmx)
			rutasInternet(r, store, mon.CheckTargets) // Internet y servicios (Go + htmx)
		})
		r.Group(func(r chi.Router) {
			r.Use(cuentas.SoloAdmin)
			auth.RutasAdmin(r)
			auth.RutasUsuariosUI(r)
		})
	})
	// cualquier otra /api/ que no exista: 404, no la página
	r.HandleFunc("/api/*", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no existe", 404) })

	// panel (todavía el index.html con JavaScript propio; sus datos piden sesión)
	r.Get("/", panelRaiz)
	r.Get("/index.html", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusMovedPermanently) })
	return r
}

// servir escucha en HTTP, o en HTTPS si hay certificado (MONITOREO_TLS_CERT y
// MONITOREO_TLS_KEY). Si están puestos y no se pueden leer, el servicio NO arranca.
func servir(port string, h http.Handler) {
	srv := func(addr string, h http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	}
	addr := ":" + port
	cert, key := os.Getenv("MONITOREO_TLS_CERT"), os.Getenv("MONITOREO_TLS_KEY")
	if cert == "" && key == "" {
		log.Printf("Monitoreo de Red %s escuchando en http://0.0.0.0%s", version, addr)
		log.Fatal(srv(addr, h).ListenAndServe())
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		log.Fatalf("HTTPS: no se pudo leer el certificado (%s, %s): %v", cert, key, err)
	}
	haddr := ":" + envOr("MONITOREO_HTTPS_PORT", "5443")
	// el puerto HTTP solo redirige a HTTPS (la API v1 sigue en HTTP para integraciones)
	go func() {
		log.Fatal(srv(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/v1/") {
				h.ServeHTTP(w, r)
				return
			}
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}
			http.Redirect(w, r, "https://"+host+haddr+r.URL.RequestURI(), http.StatusMovedPermanently)
		})).ListenAndServe())
	}()
	log.Printf("Monitoreo de Red %s escuchando en https://0.0.0.0%s (HTTP %s redirige)", version, haddr, addr)
	log.Fatal(srv(haddr, h).ListenAndServeTLS(cert, key))
}
