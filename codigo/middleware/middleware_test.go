package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			if _, err := io.ReadAll(r.Body); err != nil {
				http.Error(w, "muy grande", 413)
				return
			}
		}
		w.Write([]byte("ok"))
	})
}

func req(method, path, body string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, "http://192.168.10.200:5000"+path, strings.NewReader(body))
	r.RemoteAddr = "192.168.10.50:4000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestCabeceras(t *testing.T) {
	w := httptest.NewRecorder()
	Cabeceras(okHandler()).ServeHTTP(w, req("GET", "/api/devices", "", nil))
	h := w.Header()
	for _, k := range []string{"X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"} {
		if h.Get(k) == "" {
			t.Errorf("falta %s", k)
		}
	}
	if h.Get("Cache-Control") != "no-store" {
		t.Error("la API debe ir con no-store")
	}
	if h.Get("Strict-Transport-Security") != "" {
		t.Error("sin TLS no debe mandar HSTS")
	}
	if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("CSP sin frame-ancestors")
	}
}

func TestMismoOrigen(t *testing.T) {
	h := MismoOrigen(okHandler())
	casos := []struct {
		nombre string
		r      *http.Request
		code   int
	}{
		{"GET libre", req("GET", "/api/devices", "", map[string]string{"Sec-Fetch-Site": "cross-site"}), 200},
		{"POST mismo origen", req("POST", "/api/device", "{}", map[string]string{"Sec-Fetch-Site": "same-origin"}), 200},
		{"POST de otro sitio", req("POST", "/api/device", "{}", map[string]string{"Sec-Fetch-Site": "cross-site"}), 403},
		{"POST Origin igual (navegador viejo)", req("POST", "/api/device", "{}", map[string]string{"Origin": "http://192.168.10.200:5000"}), 200},
		{"POST Origin distinto", req("POST", "/api/device", "{}", map[string]string{"Origin": "http://malo.example"}), 403},
		{"POST sin nada", req("POST", "/api/device", "{}", nil), 403},
		{"DELETE de otro sitio", req("DELETE", "/api/device?mac=x", "", map[string]string{"Sec-Fetch-Site": "same-site"}), 403},
		{"API v1 con token (sin navegador)", req("POST", "/api/v1/algo", "{}", nil), 200},
	}
	for _, c := range casos {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.r)
		if w.Code != c.code {
			t.Errorf("%s: %d, se esperaba %d", c.nombre, w.Code, c.code)
		}
	}
}

func TestLimitarIP(t *testing.T) {
	h := LimitarIP(1, 3)(okHandler())
	codes := []int{}
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req("GET", "/", "", nil))
		codes = append(codes, w.Code)
	}
	if codes[2] != 200 || codes[3] != 429 {
		t.Fatalf("ráfaga 3 y luego 429: %v", codes)
	}
	// otra IP no se ve afectada
	r := req("GET", "/", "", nil)
	r.RemoteAddr = "192.168.10.51:4000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("otra IP debe pasar")
	}
	// por prefijo: solo /api/auth/
	hp := LimitarIP(1, 1, "/api/auth/")(okHandler())
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		hp.ServeHTTP(w, req("GET", "/api/devices", "", nil))
		if w.Code != 200 {
			t.Fatal("fuera del prefijo no limita")
		}
	}
}

func TestLimitarTamano(t *testing.T) {
	w := httptest.NewRecorder()
	LimitarTamano(okHandler()).ServeHTTP(w, req("POST", "/api/device", strings.Repeat("x", maxCuerpo+1), nil))
	if w.Code != 413 {
		t.Fatalf("cuerpo enorme: %d", w.Code)
	}
}

func TestRecuperar(t *testing.T) {
	w := httptest.NewRecorder()
	Recuperar(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("falla") })).ServeHTTP(w, req("GET", "/", "", nil))
	if w.Code != 500 {
		t.Fatalf("pánico debe dar 500: %d", w.Code)
	}
}

func TestIPReal(t *testing.T) {
	r := req("GET", "/", "", map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if IPReal(r) != "192.168.10.50" {
		t.Fatal("sin proxy declarado, X-Forwarded-For se ignora")
	}
}
