package main

// Pruebas de Configuración (Go + htmx) con una base temporal y equipos simulados.
// Corren en Windows gracias a otros_sistemas.go: go test -run Config .

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
)

func TestConfiguracion(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "datos.json"))
	store.Devs["aa:bb:cc:00:00:05@192.168.10.5"] = &Device{ID: "aa:bb:cc:00:00:05@192.168.10.5", IP: "192.168.10.5", MAC: "aa:bb:cc:00:00:05", Vendor: "HP Inc.", Hostname: "PC-CONTA"}
	store.Devs["aa:bb:cc:00:00:09@192.168.10.9"] = &Device{ID: "aa:bb:cc:00:00:09@192.168.10.9", IP: "192.168.10.9", MAC: "aa:bb:cc:00:00:09"}
	auth := cuentas.Nuevo(nil, store)
	if err := auth.SetUser("admin", "admin", "clave-prueba-1", true); err != nil {
		t.Fatal(err)
	}
	auth.SetUser("ana", "consulta", "clave-prueba-2", true)
	adm, _ := auth.Login("admin", "clave-prueba-1", "1.1.1.1")
	con, _ := auth.Login("ana", "clave-prueba-2", "1.1.1.2")

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(auth.Sesion)
		r.Group(func(r chi.Router) {
			r.Use(cuentas.PuedeCambiar)
			rutasConfig(r, store, &Monitor{}, auth)
		})
	})
	do := func(method, path, body, cookie string, htmx bool) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if htmx {
			q.Header.Set("HX-Request", "true")
		}
		if cookie != "" {
			q.AddCookie(&http.Cookie{Name: "mr_sesion", Value: cookie})
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, q)
		return w
	}
	chk := func(n string, w *httptest.ResponseRecorder, code int, has ...string) {
		t.Helper()
		if w.Code != code {
			t.Errorf("%s: código %d (esperaba %d)", n, w.Code, code)
		}
		for _, h := range has {
			if !strings.Contains(w.Body.String(), h) {
				t.Errorf("%s: falta %q", n, h)
			}
		}
	}

	chk("sin sesión → login", do("GET", "/configuracion", "", "", false), 303)
	w := do("GET", "/configuracion", "", adm, false)
	chk("página", w, 200, "Segmentos", "Usuarios", `<b>10</b>`)
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self';") {
		t.Error("Configuración debe ir con CSP estricta")
	}
	if strings.Contains(w.Body.String(), "onclick") || strings.Contains(w.Body.String(), " style=") {
		t.Error("sin JavaScript ni estilos en línea")
	}
	chk("consulta no ve Usuarios", do("GET", "/configuracion", "", con, false), 200, "Segmentos")
	if strings.Contains(do("GET", "/configuracion", "", con, false).Body.String(), ">Usuarios<") {
		t.Error("consulta no debe ver la pestaña Usuarios")
	}
	chk("fragmento sin htmx redirige", do("GET", "/configuracion/equipos?seg=10", "", adm, false), 303)

	// equipos: tabla con campos para admin, solo texto para consulta
	chk("equipos", do("GET", "/configuracion/equipos?seg=10", "", adm, true), 200, "192.168.10.5", `name="nombre"`, "PC-CONTA")
	w = do("GET", "/configuracion/equipos?seg=10", "", con, true)
	if strings.Contains(w.Body.String(), `name="nombre"`) {
		t.Error("consulta no debe poder editar")
	}
	f := url.Values{"id": {"aa:bb:cc:00:00:05@192.168.10.5"}, "nombre": {"Contabilidad 1"}, "ubicacion": {"Piso 3, <b>Contab</b>"}}
	chk("guardar equipo", do("POST", "/configuracion/equipos", f.Encode(), adm, true), 200, "guardado", "Contabilidad 1", "&lt;b&gt;Contab")
	if d, _ := store.Device("aa:bb:cc:00:00:05@192.168.10.5"); d.Name != "Contabilidad 1" || d.Location != "Piso 3, <b>Contab</b>" || !d.Known {
		t.Errorf("no se guardó: %+v", d)
	}
	chk("consulta no guarda", do("POST", "/configuracion/equipos", f.Encode(), con, true), 403)

	// segmentos
	chk("puerta de otro segmento", do("POST", "/configuracion/segmentos", url.Values{"nuevo": {"1"}, "seg": {"130"}, "puerta": {"192.168.5.1"}}.Encode(), adm, true), 200, "debe ser una IP de ese segmento")
	w = do("POST", "/configuracion/segmentos", url.Values{"seg": {"10"}, "nombre": {"Desarrollo"}, "ubicacion": {"Piso 1"}}.Encode(), adm, true)
	chk("guardar segmento", w, 200, "Segmento 10 guardado", "Desarrollo", "Piso 1", `hx-swap-oob`)
	if segLocation("10") != "Piso 1" || segName("10") != "Desarrollo" {
		t.Error("no se guardó el segmento")
	}
	chk("ventana editar", do("GET", "/configuracion/segmentos/editar?seg=10", "", adm, true), 200, `value="Desarrollo"`, "192.168.10.254")
}
