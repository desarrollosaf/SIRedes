package main

// Pruebas de Eventos (Go + htmx) con una base temporal y eventos simulados.
// Corren en Windows: go test -run Eventos .

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
)

func TestEventos(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "datos.json"))
	db, err := OpenDB(filepath.Join(dir, "datos.db"))
	if err != nil {
		t.Fatal(err)
	}
	store.db = db
	t.Cleanup(func() { db.Flush(); db.SQL().Close() })
	store.Devs["aa:bb:cc:00:00:05@192.168.10.5"] = &Device{ID: "aa:bb:cc:00:00:05@192.168.10.5", IP: "192.168.10.5", MAC: "aa:bb:cc:00:00:05"}
	ahora := time.Now()
	db.AddEvent(Event{Time: ahora, Kind: "offline", Message: "PC-CONTA se cayó <b>fuerte</b>", Seg: "10"}, "10", "")
	db.AddEvent(Event{Time: ahora, Kind: "new", Message: "Equipo nuevo aa:bb:cc:00:00:07", Seg: "10"}, "10", "")
	db.AddEvent(Event{Time: ahora, Kind: "info", Message: "Se cayó el internet"}, "", "")
	db.AddEvent(Event{Time: ahora.AddDate(0, 0, -3), Kind: "corte", Message: "Corte viejo de impresora", Seg: "10"}, "10", "")
	db.AddEvent(Event{Time: ahora.AddDate(0, 0, -10), Kind: "online", Message: "Evento de hace diez dias", Seg: "10"}, "10", "")
	db.Flush()

	auth := cuentas.Nuevo(nil, store)
	auth.SetUser("ana", "consulta", "clave-prueba-2", true)
	con, _ := auth.Login("ana", "clave-prueba-2", "1.1.1.2")

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(auth.Sesion)
		rutasEventos(r, store)
	})
	do := func(path, cookie string, cab ...string) *httptest.ResponseRecorder {
		q := httptest.NewRequest("GET", path, nil)
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
		for _, h := range has {
			if !strings.Contains(w.Body.String(), h) {
				t.Errorf("%s: falta %q", n, h)
			}
		}
	}
	no := func(n string, w *httptest.ResponseRecorder, has ...string) {
		t.Helper()
		for _, h := range has {
			if strings.Contains(w.Body.String(), h) {
				t.Errorf("%s: sobra %q", n, h)
			}
		}
	}

	chk("sin sesión → login", do("/eventos", "", "Accept", "text/html"), 303)

	// página completa (cualquier perfil): marco, filtros, lista, CSP estricta
	w := do("/eventos", con)
	chk("página", w, 200, "<!DOCTYPE html>", `class="on">Eventos`, `name="q"`, "Todos los segmentos", "Generales", "Caídas y cortes",
		"PC-CONTA se cayó &lt;b&gt;fuerte", "Caída", "Nuevo", "Se cayó el internet", "Corte viejo", "4 eventos", `id="ev-lista"`, `hx-push-url="true"`)
	no("página (7 días por omisión)", w, "diez dias")
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self';") {
		t.Error("Eventos debe ir con CSP estricta")
	}
	if strings.Contains(w.Body.String(), "onclick") || strings.Contains(w.Body.String(), " style=") {
		t.Error("sin JavaScript ni estilos en línea")
	}

	// fragmento htmx: solo la lista
	w = do("/eventos?tipo=imp&dias=7", con, "HX-Request", "true")
	chk("fragmento", w, 200, "PC-CONTA", "Corte viejo", "ev offline", "ev corte", "2 eventos")
	no("fragmento", w, "<html", "Todos los segmentos", "Se cayó el internet", "Equipo nuevo")
	// "atrás" de htmx pide la página entera
	chk("restaurar historial", do("/eventos", con, "HX-Request", "true", "HX-History-Restore-Request", "true"), 200, "<!DOCTYPE html>")

	// filtros
	w = do("/eventos?seg=-", con, "HX-Request", "true")
	chk("generales", w, 200, "Se cayó el internet", "1 evento")
	no("generales", w, "PC-CONTA")
	w = do("/eventos?seg=10&tipo=new", con, "HX-Request", "true")
	chk("segmento y tipo", w, 200, "Equipo nuevo aa:bb:cc:00:00:07", "1 evento")
	no("segmento y tipo", w, "PC-CONTA", "internet")
	chk("búsqueda", do("/eventos?q=impresora&dias=30", con, "HX-Request", "true"), 200, "Corte viejo", "1 evento")
	chk("hoy", do("/eventos?dias=1", con, "HX-Request", "true"), 200, "PC-CONTA")
	no("hoy sin el de hace 3 días", do("/eventos?dias=1&q=impresora", con, "HX-Request", "true"), "Corte viejo")
	chk("sin resultados", do("/eventos?q=nadaquecoincida", con, "HX-Request", "true"), 200, "Sin eventos", "0 eventos")
	chk("filtros inválidos", do("/eventos?tipo=x&dias=999", con, "HX-Request", "true"), 200, "4 eventos")
	chk("los filtros quedan en el formulario", do("/eventos?q=hola&tipo=con&dias=30", con), 200, `value="hola"`, `value="con" selected`, `value="30" selected`)
}
