package main

// Pruebas de Internet y servicios (Go + htmx) con una base temporal.
// Corren en Windows: go test -run Internet .

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
)

func TestInternetYServicios(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "datos.json"))
	db, err := OpenDB(filepath.Join(dir, "datos.db"))
	if err != nil {
		t.Fatal(err)
	}
	store.db = db
	t.Cleanup(func() { db.Flush(); db.SQL().Close() })
	ahora := time.Now()
	h := func(n int) int64 { return ahora.Add(-time.Duration(n) * time.Hour).Unix() }
	db.OutageStart(h(50), "")
	db.OutageEnd(h(50), h(50)+300, "proveedor <b>x</b>")
	db.OutageStart(h(80), "")
	db.OutageEnd(h(80), h(80), "la Pi se apagó o reinició durante el corte")
	db.Flush()
	store.AddTarget(Target{Name: "DNS Google", Host: "8.8.8.8"})
	time.Sleep(20 * time.Millisecond) // newID usa la hora: dos altas seguidas pueden repetirse en Windows
	store.AddTarget(Target{Name: "Servidor <i>web</i>", Host: "192.168.10.20", Port: 443})
	store.TargetResult(store.Targets()[0].ID, 12.3, true)
	store.TargetResult(store.Targets()[1].ID, 0, false)

	auth := cuentas.Nuevo(nil, store)
	auth.SetUser("oscar", "operador", "clave-prueba-3", true)
	auth.SetUser("ana", "consulta", "clave-prueba-2", true)
	ope, _ := auth.Login("oscar", "clave-prueba-3", "1.1.1.1")
	con, _ := auth.Login("ana", "clave-prueba-2", "1.1.1.2")

	revisadas := make(chan struct{}, 4)
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(auth.Sesion)
		r.Group(func(r chi.Router) {
			r.Use(cuentas.PuedeCambiar)
			rutasInternet(r, store, func() { revisadas <- struct{}{} })
		})
	})
	do := func(method, path, body, cookie string, cab ...string) *httptest.ResponseRecorder {
		q := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for i := 0; i+1 < len(cab); i += 2 {
			q.Header.Set(cab[i], cab[i+1])
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
		for _, s := range has {
			if !strings.Contains(w.Body.String(), s) {
				t.Errorf("%s: falta %q", n, s)
			}
		}
	}
	no := func(n string, w *httptest.ResponseRecorder, has ...string) {
		t.Helper()
		for _, s := range has {
			if strings.Contains(w.Body.String(), s) {
				t.Errorf("%s: sobra %q", n, s)
			}
		}
	}

	chk("sin sesión → login", do("GET", "/internet", "", "", "Accept", "text/html"), 303)

	// página completa (operador): marco, estado, cortes con causa, barras, servicios con ✕ y formulario
	w := do("GET", "/internet", "", ope)
	chk("página", w, 200, "<!DOCTYPE html>", `class="on">Internet y servicios`, "Con internet", "último corte", `id="in-datos"`,
		`hx-trigger="every 5s"`, "Hoy", "7 días", "30 días", "Día", "Causa", "proveedor &lt;b&gt;x&lt;/b&gt;", "5 min", "no se sabe",
		`class="dias30"`, "DNS Google", "12.3 ms", "sin respuesta", "192.168.10.20:443", "Servidor &lt;i&gt;web",
		`hx-delete="/internet/servicios?id=`, `hx-confirm="`, `hx-post="/internet/servicios"`, "Agregar servicio")
	if n := strings.Count(w.Body.String(), `<li class="`); n != 30 {
		t.Errorf("barras: %d (esperaba 30)", n)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self';") {
		t.Error("Internet debe ir con CSP estricta")
	}
	if strings.Contains(w.Body.String(), "onclick") || strings.Contains(w.Body.String(), " style=") {
		t.Error("sin JavaScript ni estilos en línea")
	}

	// consulta: ve todo, pero sin controles
	w = do("GET", "/internet", "", con)
	chk("consulta ve datos", w, 200, "DNS Google", "proveedor")
	no("consulta sin controles", w, "hx-delete", "hx-post", "Agregar servicio")
	no("consulta (fragmento)", do("GET", "/internet", "", con, "HX-Request", "true"), "hx-delete")

	// fragmento htmx y "atrás"
	w = do("GET", "/internet", "", ope, "HX-Request", "true")
	chk("fragmento", w, 200, `id="in-datos"`, "DNS Google")
	no("fragmento", w, "<html", "Agregar servicio")
	chk("restaurar historial", do("GET", "/internet", "", ope, "HX-Request", "true", "HX-History-Restore-Request", "true"), 200, "<!DOCTYPE html>")

	// corte abierto: estado grande en rojo
	db.OutageStart(ahora.Add(-10*time.Minute).Unix(), "")
	db.Flush()
	chk("sin internet", do("GET", "/internet", "", ope, "HX-Request", "true"), 200, "Sin internet", "sigue", "alarmed")
	db.OutageEnd(ahora.Add(-10*time.Minute).Unix(), ahora.Unix(), "router o cable")
	db.Flush()
	chk("causa router", do("GET", "/internet", "", ope, "HX-Request", "true"), 200, "router o cable")

	// agregar
	f := url.Values{"nombre": {"Impresora"}, "host": {"192.168.10.30"}, "puerto": {"9100"}}
	w = do("POST", "/internet/servicios", f.Encode(), ope, "HX-Request", "true")
	chk("agregar", w, 200, "Impresora", "192.168.10.30:9100", "agregado", "revisando", `hx-swap-oob="true"`)
	if len(store.Targets()) != 3 {
		t.Errorf("servicios: %d (esperaba 3)", len(store.Targets()))
	}
	select {
	case <-revisadas:
	case <-time.After(2 * time.Second):
		t.Error("no pidió revisar el servicio nuevo")
	}
	chk("sin nombre usa el host", do("POST", "/internet/servicios", url.Values{"host": {"1.1.1.1"}}.Encode(), ope, "HX-Request", "true"), 200, "Servicio 1.1.1.1 agregado")
	for n, v := range map[string]url.Values{
		"sin host":      {"nombre": {"x"}},
		"host raro":     {"host": {"-oProxy=x; ls"}},
		"puerto malo":   {"host": {"192.168.10.31"}, "puerto": {"99999"}},
		"puerto letras": {"host": {"192.168.10.31"}, "puerto": {"abc"}},
	} {
		w = do("POST", "/internet/servicios", v.Encode(), ope, "HX-Request", "true")
		chk(n, w, 200, `class="error"`)
		no(n, w, `hx-swap-oob`)
	}
	if len(store.Targets()) != 4 {
		t.Errorf("servicios tras errores: %d (esperaba 4)", len(store.Targets()))
	}
	chk("consulta no agrega", do("POST", "/internet/servicios", f.Encode(), con, "HX-Request", "true"), 403)

	// quitar
	id := store.Targets()[0].ID
	chk("consulta no quita", do("DELETE", "/internet/servicios?id="+url.QueryEscape(id), "", con, "HX-Request", "true"), 403)
	if len(store.Targets()) != 4 {
		t.Error("consulta quitó un servicio")
	}
	w = do("DELETE", "/internet/servicios?id="+url.QueryEscape(id), "", ope, "HX-Request", "true")
	chk("quitar", w, 200, "Servicio quitado", "Impresora")
	no("quitar", w, "DNS Google")
	if len(store.Targets()) != 3 {
		t.Errorf("servicios tras quitar: %d (esperaba 3)", len(store.Targets()))
	}
}
