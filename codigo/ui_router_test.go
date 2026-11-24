package main

// Pruebas del Router (Go + htmx) con un router SNMP simulado. Corren en Windows: go test -run Router .

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/app/cuentas"
	"monitoreo/web"
)

func TestRouter(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "datos.json"))
	store.Devs["aa:bb:cc:00:00:05@192.168.10.5"] = &Device{ID: "aa:bb:cc:00:00:05@192.168.10.5", IP: "192.168.10.5", MAC: "aa:bb:cc:00:00:05", Hostname: "PC-CONTA <b>", Vendor: "HP Inc."}
	auth := cuentas.Nuevo(nil, store)
	auth.SetUser("ana", "consulta", "clave-prueba-2", true)
	con, _ := auth.Login("ana", "clave-prueba-2", "1.1.1.2")

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(auth.Sesion)
		rutasRouter(r, store)
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
	t.Cleanup(func() { snmpMon = nil; web.RouterActivo = func() bool { return false } })

	chk("sin sesión → login", do("/router", "", "Accept", "text/html"), 303)
	chk("segmento sin sesión → login", do("/router/segmento?red=192.168.10.0/24", "", "Accept", "text/html"), 303)

	// SNMP apagado: solo un aviso
	snmpMon = nil
	web.RouterActivo = func() bool { return false }
	w := do("/router", con)
	chk("inactivo", w, 200, "<!DOCTYPE html>", "El router no está configurado", `id="rt-datos"`)
	no("inactivo", w, "Cables", `href="/router"`)
	no("inactivo (fragmento)", do("/router", con, "HX-Request", "true"), "<html")
	chk("ventana inactiva", do("/router/segmento?red=192.168.10.0/24", con), 200, "no tiene equipos")

	// router simulado
	ahora := time.Now()
	desde := ahora.Add(-time.Minute)
	snmpMon = &SNMPMon{
		state: SNMPState{
			Active: true, Name: "Router 10", IP: "192.168.10.254", SysName: "edge <i>1", SysDescr: "EdgeOS v3", Uptime: 3*86400 + 5, Last: &ahora,
			Inet: SNMPInet{Estado: "sospecha", Motivo: "casi no regresa tráfico", Desde: &desde, Bajada: 0.3, Subida: 0.1, Local: 12.5, Rapida: true, Horario: false},
			Ifaces: []SNMPIface{
				{Index: 1, Name: "eth0", Alias: "Internet", Up: true, AdminUp: true, SpeedMbps: 1000, InMbps: 40, OutMbps: 8, Internet: true,
					Segmentos: []SNMPSeg{{Red: "192.168.30.0/24", Equipos: 1}}},
				{Index: 2, Name: "eth1", Alias: "Local", Up: true, AdminUp: true, SpeedMbps: 1000, InMbps: 6, OutMbps: 30, Equipos: 2,
					ErrActive: true, Errors: 4, ErrorTotal: 12345,
					Segmentos: []SNMPSeg{{Red: "192.168.10.0/24", Router: "192.168.10.254", Equipos: 2}, {Red: "192.168.20.0/24", Equipos: 0}}},
				{Index: 3, Name: "eth2", AdminUp: true, Up: false, Fell: true, SpeedMbps: 100, Equipos: 1},
				{Index: 4, Name: "imq0", AdminUp: true, Up: true},
			},
		},
		extra: rtExtra{arp: map[string]arpEnt{
			"192.168.10.5": {mac: "aa:bb:cc:00:00:05", ifIndex: 2},
			"192.168.10.7": {mac: "aa:bb:cc:00:00:07", ifIndex: 2},
		}},
	}
	web.RouterActivo = func() bool { return true }

	w = do("/router", con)
	chk("página", w, 200, "<!DOCTYPE html>", `class="on">Router`, `href="/router"`, "Router 10 · edge &lt;i&gt;1", "192.168.10.254", "EdgeOS v3 · encendido 3 días",
		"<h2>Internet</h2>", "eth0", "Internet", "↓ 0.3 Mb/s", "↑ 0.1 Mb/s", "Revisando: casi no regresa tráfico de internet", "desde "+desde.Format("15:04"),
		"Cada 5 s: equipos → router 12.5 Mb/s · regresa de internet 0.3 Mb/s · fuera de horario solo se vigila el puerto",
		"<h2>Cables</h2>", "eth1", "↓ 30.0 Mb/s", "↑ 6.0 Mb/s", "4 en 30 s", "12,345 acumulados", `<progress class="pct" max="100" value="75"`,
		"75 % de lo que baja de internet", "● arriba · 1 Gb/s", "● caída", "192.168.10.0/24", "puerta 192.168.10.254", "ruta directa", "2 equipos", "0 equipos", "1 equipo",
		`hx-trigger="every 5s"`, `hx-get="/router/segmento?red=192.168.10.0%2F24&puerta=192.168.10.254"`)
	no("página (imq0 interna oculta)", w, "imq0")
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self';") {
		t.Error("Router debe ir con CSP estricta")

	}
	if strings.Contains(w.Body.String(), "onclick") || strings.Contains(w.Body.String(), " style=") {
		t.Error("sin JavaScript ni estilos en línea")
	}

	// fragmento htmx: solo los datos (con el disparador para seguir refrescando)
	w = do("/router", con, "HX-Request", "true")
	chk("fragmento", w, 200, `id="rt-datos"`, `hx-trigger="every 5s"`, "Router 10")
	no("fragmento", w, "<html", "Eventos")
	chk("restaurar historial", do("/router", con, "HX-Request", "true", "HX-History-Restore-Request", "true"), 200, "<!DOCTYPE html>")

	// sin respuesta SNMP
	snmpMon.state.Down = true
	chk("sin respuesta", do("/router", con), 200, "no responde por SNMP", "alarmed")
	snmpMon.state.Down = false

	// ventana de un segmento
	w = do("/router/segmento?red=192.168.10.0/24&puerta=192.168.10.254", con, "HX-Request", "true")
	chk("ventana", w, 200, "192.168.10.0/24", "puerta 192.168.10.254", "2 equipos en la tabla ARP del router", "192.168.10.5", "aa:bb:cc:00:00:07",
		"PC-CONTA &lt;b&gt;", "HP Inc.", `data-cerrar`, `href="/dispositivos?dev=aa%3Abb%3Acc%3A00%3A00%3A05%40192.168.10.5&ip=192.168.10.5"`)
	no("ventana", w, "<html", "PC-CONTA <b>")
	// el equipo que la Pi no conoce no lleva enlace
	if strings.Count(w.Body.String(), "dev=") != 2 {
		t.Errorf("solo el equipo conocido lleva enlace (2 por fila): %d", strings.Count(w.Body.String(), "dev="))
	}
	chk("ventana sin equipos", do("/router/segmento?red=192.168.20.0/24", con), 200, "ruta directa", "no tiene equipos de este segmento")
	chk("ventana con red inválida", do("/router/segmento?red=hola", con), 400)
}
