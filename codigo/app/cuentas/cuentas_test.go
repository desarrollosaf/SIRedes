package cuentas

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

type evs struct{ n []string }

func (e *evs) AddEvent(k, m string) { e.n = append(e.n, m) }

// router como el de servidor.go, con rutas de datos de mentira
func armar(a *Auth) http.Handler {
	r := chi.NewRouter()
	a.RutasPublicas(r)
	r.Group(func(r chi.Router) {
		r.Use(a.Sesion)
		r.Group(func(r chi.Router) {
			r.Use(PuedeCambiar)
			r.Get("/api/devices", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("lista")) })
			r.Post("/api/device", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("guardado")) })
		})
		r.Group(func(r chi.Router) {
			r.Use(SoloAdmin)
			a.RutasAdmin(r)
		})
	})
	return r
}

type cliente struct {
	t  *testing.T
	h  http.Handler
	ip int
}

func (c *cliente) do(method, path, body, cookie string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	c.ip++
	r.RemoteAddr = "10.0." + string(rune('0'+c.ip/10%10)) + "." + string(rune('0'+c.ip%10)) + ":1"
	if body != "" && !strings.HasPrefix(body, "{") {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	return w
}

func galleta(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			return c.Value
		}
	}
	return ""
}

func form(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v.Encode()
}

func TestLoginYPerfiles(t *testing.T) {
	ev := &evs{}
	a := Nuevo(nil, ev)
	c := &cliente{t: t, h: armar(a)}
	chk := func(nombre string, w *httptest.ResponseRecorder, code int, has string) {
		t.Helper()
		if w.Code != code || !strings.Contains(w.Body.String(), has) {
			t.Errorf("%s: %d %q (esperaba %d con %q)", nombre, w.Code, w.Body.String(), code, has)
		}
	}
	hx := []string{"HX-Request", "true"}

	// página de entrada: primera vez, sin JavaScript ni estilos en línea
	w := c.do("GET", "/login", "", "")
	chk("login primera vez", w, 200, "crea la cuenta de administrador")
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self';") {
		t.Error("el login debe ir con CSP estricta")
	}
	if strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), "style=") || strings.Contains(w.Body.String(), "onclick") {
		t.Error("el login no debe tener JavaScript ni estilos en línea")
	}
	chk("/login.html redirige", c.do("GET", "/login.html", "", ""), 301, "")

	// primer admin con htmx
	chk("claves distintas", c.do("POST", "/login", form("usuario", "admin", "clave", "clave-prueba-1", "clave2", "otra-clave-9"), "", hx...), 200, "no coinciden")
	chk("clave corta", c.do("POST", "/login", form("usuario", "admin", "clave", "corta", "clave2", "corta"), "", hx...), 200, "8 caracteres")
	w = c.do("POST", "/login", form("usuario", "Admin", "clave", "clave-prueba-1", "clave2", "clave-prueba-1"), "", hx...)
	adm := galleta(w)
	if w.Code != 204 || w.Header().Get("HX-Redirect") != "/" || adm == "" {
		t.Fatalf("primer admin con htmx: %d %q cookie=%v", w.Code, w.Header().Get("HX-Redirect"), adm != "")
	}
	chk("con sesión, /login manda al panel", c.do("GET", "/login", "", adm), 303, "")
	chk("ya no es primera vez", c.do("GET", "/login", "", ""), 200, "Inicia sesión")

	// errores: con htmx solo el texto; sin htmx la página entera, escapada
	chk("clave mala (htmx)", c.do("POST", "/login", form("usuario", "admin", "clave", "mala-mala-1"), "", hx...), 200, "incorrectos")
	w = c.do("POST", "/login", form("usuario", `<script>x</script>`, "clave", "mala-mala-1"), "")
	chk("clave mala (sin htmx)", w, 401, "incorrectos")
	if strings.Contains(w.Body.String(), "<script>x") {
		t.Error("lo escrito debe salir escapado")
	}
	w = c.do("POST", "/login", form("usuario", "admin", "clave", "clave-prueba-1"), "")
	if w.Code != 303 || galleta(w) == "" {
		t.Fatalf("entrada sin htmx: %d", w.Code)
	}

	// perfiles
	chk("sin sesión", c.do("GET", "/api/devices", "", ""), 401, "")
	chk("crear consulta", c.do("POST", "/api/usuarios", `{"usuario":"ana","perfil":"consulta","clave":"clave-prueba-2","nuevo":true}`, adm), 200, "ok")
	chk("crear operador", c.do("POST", "/api/usuarios", `{"usuario":"luis","perfil":"operador","clave":"clave-prueba-3","nuevo":true}`, adm), 200, "ok")
	con := galleta(c.do("POST", "/login", form("usuario", "ana", "clave", "clave-prueba-2"), "", hx...))
	op := galleta(c.do("POST", "/login", form("usuario", "luis", "clave", "clave-prueba-3"), "", hx...))
	chk("consulta ve", c.do("GET", "/api/devices", "", con), 200, "lista")
	chk("consulta no cambia", c.do("POST", "/api/device", "{}", con), 403, "")
	chk("consulta no ve cuentas", c.do("GET", "/api/usuarios", "", con), 403, "")
	chk("operador cambia", c.do("POST", "/api/device", "{}", op), 200, "guardado")
	chk("operador no ve bitácora", c.do("GET", "/api/seguridad", "", op), 403, "")
	chk("admin ve cuentas", c.do("GET", "/api/usuarios", "", adm), 200, "luis")
	chk("quién soy", c.do("GET", "/api/auth/sesion", "", op), 200, `"perfil":"operador"`)
	chk("último admin", c.do("POST", "/api/usuarios", `{"usuario":"admin","perfil":"operador"}`, adm), 400, "administrador")

	// cambiar clave cierra las otras sesiones
	op2 := galleta(c.do("POST", "/login", form("usuario", "luis", "clave", "clave-prueba-3"), "", hx...))
	w = c.do("POST", "/api/auth/clave", `{"actual":"clave-prueba-3","nueva":"clave-nueva-33"}`, op)
	chk("cambiar clave", w, 200, "ok")
	chk("otra sesión cerrada", c.do("GET", "/api/devices", "", op2), 401, "")
	chk("sesión nueva sirve", c.do("GET", "/api/devices", "", galleta(w)), 200, "lista")

	// salir
	c.do("POST", "/api/auth/salir", "", con)
	chk("tras salir", c.do("GET", "/api/devices", "", con), 401, "")

	// bloqueo por intentos desde la misma IP
	fija := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/login", strings.NewReader(body))
		r.RemoteAddr = "10.9.9.9:1"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("HX-Request", "true")
		w := httptest.NewRecorder()
		c.h.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < loginMaxFail; i++ {
		fija(form("usuario", "ana", "clave", "mala-mala-1"))
	}
	chk("bloqueado", fija(form("usuario", "ana", "clave", "clave-prueba-2")), 200, "intentos")
	t.Log(ev.n)
}
