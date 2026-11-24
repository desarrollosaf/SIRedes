package main

// Pruebas de Dispositivos (Go + htmx) con una base temporal y equipos simulados.
// Corren en Windows: go test -run Dispositivos .

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

func TestDispositivos(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "datos.json"))
	ahora := time.Now()
	const id5 = "aa:bb:cc:00:00:05@192.168.10.5"
	hist := []Point{{T: ahora.Unix() - 90, Ms: 3.2}, {T: ahora.Unix() - 60, Ms: -1}, {T: ahora.Unix() - 30, Ms: 4.5}, {T: ahora.Unix(), Ms: 3.9}}
	store.Devs[id5] = &Device{ID: id5, IP: "192.168.10.5", MAC: "aa:bb:cc:00:00:05", Hostname: "PC-CONTA <b>", Vendor: "HP Inc.", Online: true,
		LatencyMs: 3.9, Answers: true, upSinceStart: true, FirstSeen: ahora, Kind: "windows", Ports: []int{80, 445}, History: hist}
	store.Devs["aa:bb:cc:00:00:06@192.168.10.6"] = &Device{ID: "aa:bb:cc:00:00:06@192.168.10.6", IP: "192.168.10.6", MAC: "aa:bb:cc:00:00:06",
		Vendor: macPrivada, Online: true, Answers: true, upSinceStart: true, FirstSeen: ahora, Ports: []int{8080}}
	store.Devs["aa:bb:cc:00:00:07@192.168.10.7"] = &Device{ID: "aa:bb:cc:00:00:07@192.168.10.7", IP: "192.168.10.7", MAC: "aa:bb:cc:00:00:07",
		Name: "Impresora piso 2", Known: true, Answers: true, upSinceStart: true, Kind: "impresora", FirstSeen: ahora} // desconectada
	store.Devs["aa:bb:cc:00:00:08@192.168.20.8"] = &Device{ID: "aa:bb:cc:00:00:08@192.168.20.8", IP: "192.168.20.8", MAC: "aa:bb:cc:00:00:08",
		Name: "Servidor", Known: true, Online: true, Answers: true, upSinceStart: true, FirstSeen: ahora}
	store.segNet = map[string]string{"10": "ok", "20": "sin"}

	auth := cuentas.Nuevo(nil, store)
	auth.SetUser("admin", "admin", "clave-prueba-1", true)
	auth.SetUser("ana", "consulta", "clave-prueba-2", true)
	adm, _ := auth.Login("admin", "clave-prueba-1", "1.1.1.1")
	con, _ := auth.Login("ana", "clave-prueba-2", "1.1.1.2")

	escaneos := 0
	lanzarEscaneo = func(*Monitor) { escaneos++ }
	t.Cleanup(func() { lanzarEscaneo = func(m *Monitor) { go m.Scan() }; snmpMon = nil })

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(auth.Sesion)
		r.Group(func(r chi.Router) {
			r.Use(cuentas.PuedeCambiar)
			rutasDispositivos(r, store, &Monitor{})
		})
	})
	r.Get("/", panelRaiz)
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

	// sin sesión → entrada
	chk("sin sesión", do("GET", "/dispositivos", "", "", "Accept", "text/html"), 303)
	chk("segmento sin sesión", do("GET", "/dispositivos/segmento?seg=10", "", "", "Accept", "text/html"), 303)
	chk("equipo sin sesión", do("GET", "/dispositivos/equipo?id="+url.QueryEscape(id5), "", "", "Accept", "text/html"), 303)

	// página: segmentos cerrados, con su carga al abrir; sin JavaScript ni estilos en línea
	w := do("GET", "/dispositivos", "", adm)
	chk("página", w, 200, "<!DOCTYPE html>", `class="on">Dispositivos`, `href="/dispositivos"`, `id="dv-lista"`, `hx-trigger="every 30s, dv-refrescar from:body"`,
		"Segmento 10", "Segmento 20", `<b>2</b><span class="sub">conectados`, `<b>1</b><span class="sub">conectados`, "· 1 desconectados", "Internet OK", "Sin internet", "<details", `hx-trigger="toggle once"`,
		`hx-get="/dispositivos/segmento?seg=10&amp;q=&amp;f="`, `id="dv-plegar"`, "2 segmentos", `name="abierto" value="10"`, `href="/configuracion?tab=segmentos"`,
		`hx-post="/dispositivos/escanear"`, "Todos los segmentos (2)", "Desconectados (1)", `value="" selected`)
	no("página (nada abierto)", w, "PC-CONTA", "Cargando…</div></div></details><details open")
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self';") {
		t.Error("Dispositivos debe ir con CSP estricta")
	}
	if strings.Contains(w.Body.String(), "onclick") || strings.Contains(w.Body.String(), " style=") {
		t.Error("sin JavaScript ni estilos en línea")
	}
	if !strings.Contains(w.Body.String(), `<option value="unk" hidden>Por identificar`) {
		t.Error("'Por identificar' debe ir oculta en el menú")
	}
	// consulta: sin botón de escanear
	no("consulta sin escanear", do("GET", "/dispositivos", "", con), `hx-post="/dispositivos/escanear"`)

	// fragmento htmx: solo la lista; los abiertos vienen con su tabla
	w = do("GET", "/dispositivos?abierto=10", "", adm, "HX-Request", "true")
	chk("fragmento con abierto", w, 200, `id="dv-lista"`, "<details", ` open`, "PC-CONTA &lt;b&gt;", "192.168.10.5", "Windows", "3.9 ms", "por identificar", "Celular (MAC privada)")
	no("fragmento", w, "<html", "PC-CONTA <b>", "Servidor", "Impresora piso 2")
	chk("restaurar historial", do("GET", "/dispositivos", "", adm, "HX-Request", "true", "HX-History-Restore-Request", "true"), 200, "<!DOCTYPE html>")

	// fragmento de un segmento (al abrirlo)
	w = do("GET", "/dispositivos/segmento?seg=10", "", adm, "HX-Request", "true")
	chk("segmento", w, 200, "<table>", "PC-CONTA &lt;b&gt;", "aa", "Conectado", "ind-ok", "PC con Windows", "Cable", "por identificar")
	no("segmento", w, "<html", "Impresora piso 2", "Servidor") // desconectada y de otro segmento
	chk("segmento sin internet", do("GET", "/dispositivos/segmento?seg=20", "", adm, "HX-Request", "true"), 200, "Servidor", "Sin internet", "ind-bad")
	chk("segmento vacío", do("GET", "/dispositivos/segmento?seg=99", "", adm, "HX-Request", "true"), 200, "Sin equipos conectados")

	// filtros: desconectados, búsqueda, sin internet, por identificar
	w = do("GET", "/dispositivos?f=gone", "", adm, "HX-Request", "true")
	chk("desconectados", w, 200, "Impresora piso 2", "Desconectado", "open") // un solo segmento: se abre solo
	no("desconectados", w, "PC-CONTA")
	w = do("GET", "/dispositivos?q=servidor", "", adm, "HX-Request", "true")
	chk("búsqueda", w, 200, "Servidor", "Segmento 20")
	no("búsqueda", w, "Segmento 10")
	w = do("GET", "/dispositivos?f=noinet", "", adm, "HX-Request", "true")
	chk("sin internet", w, 200, "Servidor")
	no("sin internet", w, "PC-CONTA")
	w = do("GET", "/dispositivos?f=unk", "", adm, "HX-Request", "true")
	chk("por identificar", w, 200, "por identificar")
	chk("por identificar visible si está elegida", do("GET", "/dispositivos?f=unk", "", adm), 200, `<option value="unk" selected>`)
	chk("sin coincidencias", do("GET", "/dispositivos?q=zzzz", "", adm, "HX-Request", "true"), 200, "Ningún equipo coincide.")
	chk("filtro inválido se ignora", do("GET", "/dispositivos?f=<script>&seg=raro", "", adm, "HX-Request", "true"), 200, "Segmento 10")
	chk("segmento elegido se abre", do("GET", "/dispositivos?seg=20", "", adm, "HX-Request", "true"), 200, "Servidor")
	chk("todos", do("GET", "/dispositivos?f=all&seg=10", "", adm, "HX-Request", "true"), 200, "Impresora piso 2", "PC-CONTA")
	// el filtro viaja al abrir un segmento
	chk("filtro en el segmento", do("GET", "/dispositivos?f=all&q=192", "", adm, "HX-Request", "true"), 200, `f=all`, `q=192`)

	// enlace profundo: abre el segmento y la ventana del equipo
	w = do("GET", "/dispositivos?dev="+url.QueryEscape(id5)+"&ip=192.168.10.5", "", adm)
	chk("enlace profundo", w, 200, "PC-CONTA &lt;b&gt;", `hx-trigger="load"`, `hx-get="/dispositivos/equipo?id=aa%3Abb%3Acc%3A00%3A00%3A05%4019`)
	no("enlace profundo", do("GET", "/dispositivos?dev=noexiste&ip=192.168.10.99", "", adm), `hx-trigger="load"`)

	// ventana del equipo
	w = do("GET", "/dispositivos/equipo?id="+url.QueryEscape(id5), "", adm, "HX-Request", "true")
	chk("detalle", w, 200, `data-cerrar`, "PC-CONTA &lt;b&gt;", "(probable)", "192.168.10.5", "aa:bb:cc:00:00:05", "HP Inc.", "3.9 ms", "Pings perdidos (1 h)", "Visto por 1.ª vez",
		"445 · Carpetas compartidas Windows", `<svg class="graf"`, `<path class="g-lin"`, `hx-get="/dispositivos/grafica?id=`,
		"Editar nombre y ubicación", "Promedio")
	no("detalle", w, "PC-CONTA <b>", "Cómo identificarlo", "<html", "Router") // tiene nombre; sin SNMP
	if strings.Contains(w.Body.String(), "onclick") || strings.Contains(w.Body.String(), " style=") {
		t.Error("detalle: sin JavaScript ni estilos en línea")
	}
	w = do("GET", "/dispositivos/equipo?id="+url.QueryEscape("aa:bb:cc:00:00:06@192.168.10.6"), "", con, "HX-Request", "true")
	chk("detalle por identificar", w, 200, "Cómo identificarlo", "MAC privada: probablemente un celular", "Desconecta el equipo", `href="http://192.168.10.6:8080"`, "8080 · Página web alterna")
	no("detalle consulta no edita", w, "Editar nombre")
	chk("detalle de equipo que ya no existe", do("GET", "/dispositivos/equipo?id=nada", "", adm, "HX-Request", "true"), 200, "ya no está en la lista")

	// línea del router por SNMP
	ya := time.Now()
	snmpMon = &SNMPMon{state: SNMPState{Active: true, Name: "Router 10", IP: "192.168.10.254", Last: &ya},
		extra: rtExtra{arp: map[string]arpEnt{"192.168.10.5": {mac: "aa:bb:cc:00:00:05", ifIndex: 2}, "192.168.10.6": {mac: "aa:bb:cc:99:99:99", ifIndex: 2}}}}
	chk("router lo ve", do("GET", "/dispositivos/equipo?id="+url.QueryEscape(id5), "", adm, "HX-Request", "true"), 200, "Router 10", "lo ve")
	chk("router otra MAC", do("GET", "/dispositivos/equipo?id="+url.QueryEscape("aa:bb:cc:00:00:06@192.168.10.6"), "", adm, "HX-Request", "true"), 200, "lo tiene con otra MAC: aa:bb:cc:99:99:99")
	snmpMon = nil

	// gráfica
	for _, rg := range []string{"1h", "24h", "7d"} {
		chk("gráfica "+rg, do("GET", "/dispositivos/grafica?id="+url.QueryEscape(id5)+"&r="+rg, "", adm, "HX-Request", "true"), 200, `id="dv-graf"`, "<svg")
	}
	chk("gráfica sin datos", do("GET", "/dispositivos/grafica?id="+url.QueryEscape("aa:bb:cc:00:00:08@192.168.20.8")+"&r=24h", "", adm, "HX-Request", "true"), 200, "Aún no hay datos")
	chk("gráfica de equipo que no existe", do("GET", "/dispositivos/grafica?id=nada", "", adm, "HX-Request", "true"), 404)

	// editar: operador sí, consulta no
	chk("ventana editar", do("GET", "/dispositivos/editar?id="+url.QueryEscape(id5), "", adm, "HX-Request", "true"), 200, `name="nombre"`, `name="ubicacion"`, `name="tipo"`, "Automático", "Impresora")
	chk("consulta no abre editar", do("GET", "/dispositivos/editar?id="+url.QueryEscape(id5), "", con, "HX-Request", "true"), 403)
	f := url.Values{"id": {id5}, "nombre": {"Contabilidad 1"}, "ubicacion": {"Piso 3, <b>Contab</b>"}, "tipo": {"impresora"}}
	w = do("POST", "/dispositivos/equipo", f.Encode(), adm, "HX-Request", "true")
	chk("guardar", w, 200)
	if w.Header().Get("HX-Trigger") != "dv-refrescar" || w.Body.Len() != 0 {
		t.Errorf("guardar debe cerrar la ventana y pedir la lista: %q %q", w.Header().Get("HX-Trigger"), w.Body.String())
	}
	if d, _ := store.Device(id5); d.Name != "Contabilidad 1" || d.Location != "Piso 3, <b>Contab</b>" || !d.Known || d.KindManual != "impresora" || d.Kind != "impresora" {
		t.Errorf("no se guardó: %+v", d)
	}
	chk("guardado se ve escapado", do("GET", "/dispositivos/equipo?id="+url.QueryEscape(id5), "", adm, "HX-Request", "true"), 200, "Contabilidad 1", "Piso 3, &lt;b&gt;Contab&lt;/b&gt;", "Impresora")
	chk("ventana editar con tipo fijado", do("GET", "/dispositivos/editar?id="+url.QueryEscape(id5), "", adm, "HX-Request", "true"), 200, `<option value="impresora" selected>`)

	// tipo "auto" quita el fijado
	f.Set("tipo", "auto")
	chk("tipo auto", do("POST", "/dispositivos/equipo", f.Encode(), adm, "HX-Request", "true"), 200)
	if d, _ := store.Device(id5); d.KindManual != "" {
		t.Errorf("auto debe quitar el tipo fijado: %+v", d)
	}
	// tipo inválido: la ventana vuelve con el error y no cambia nada
	f.Set("tipo", "nave-espacial")
	f.Set("nombre", "Otro nombre")
	w = do("POST", "/dispositivos/equipo", f.Encode(), adm, "HX-Request", "true")
	chk("tipo inválido", w, 200, "no es válido", `name="tipo"`)
	if d, _ := store.Device(id5); d.Name != "Contabilidad 1" {
		t.Errorf("con tipo inválido no debe cambiar nada: %+v", d)
	}
	// sin campo tipo no se toca el tipo; nombre vacío = ya no "conocido"
	store.UpdateDevice(id5, "x", "", true, ptr("laptop"))
	f.Del("tipo")
	f.Set("nombre", "")
	chk("sin tipo", do("POST", "/dispositivos/equipo", f.Encode(), adm, "HX-Request", "true"), 200)
	if d, _ := store.Device(id5); d.KindManual != "laptop" || d.Known || d.Name != "" {
		t.Errorf("sin campo tipo no debe tocar el tipo: %+v", d)
	}
	chk("consulta no guarda", do("POST", "/dispositivos/equipo", f.Encode(), con, "HX-Request", "true"), 403)
	chk("equipo inexistente", do("POST", "/dispositivos/equipo", url.Values{"id": {"nada"}}.Encode(), adm, "HX-Request", "true"), 404)

	// escanear: solo operador+
	chk("escanear", do("POST", "/dispositivos/escanear", "", adm, "HX-Request", "true"), 200, "disabled", `hx-get="/dispositivos/escanear"`)
	if escaneos != 1 {
		t.Errorf("debía lanzar un escaneo: %d", escaneos)
	}
	chk("consulta no escanea", do("POST", "/dispositivos/escanear", "", con, "HX-Request", "true"), 403)
	w = do("GET", "/dispositivos/escanear", "", adm, "HX-Request", "true")
	chk("escaneo terminado", w, 200, `hx-post="/dispositivos/escanear"`)
	if w.Header().Get("HX-Trigger") != "dv-refrescar" {
		t.Error("al terminar el escaneo se debe pedir la lista")
	}

	// demostración de alerta: el segmento más grande aparece caído
	chk("demo", do("GET", "/dispositivos?demo=1", "", adm), 200, "SIN RESPUESTA", `name="demo"`)
	no("sin demo", do("GET", "/dispositivos", "", adm), "SIN RESPUESTA")

	// /?tab=dispositivos redirige conservando dev e ip
	w = do("GET", "/?tab=dispositivos&dev="+url.QueryEscape(id5)+"&ip=192.168.10.5", "", "")
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/dispositivos?") ||
		!strings.Contains(w.Header().Get("Location"), "dev=aa%3Abb") || !strings.Contains(w.Header().Get("Location"), "ip=192.168.10.5") {
		t.Errorf("redirección: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w = do("GET", "/?tab=dispositivos", "", ""); w.Header().Get("Location") != "/dispositivos" {
		t.Errorf("redirección simple: %q", w.Header().Get("Location"))
	}
}

func ptr(s string) *string { return &s }
