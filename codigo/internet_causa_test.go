package main

import (
	"sync"
	"testing"
	"time"
)

func TestInetCausa(t *testing.T) {
	casos := []struct {
		seen, fail bool
		want       string
	}{
		{false, false, ""},
		{false, true, ""},
		{true, false, "proveedor"},
		{true, true, "router o cable"},
	}
	for _, c := range casos {
		if got := inetCausa(c.seen, c.fail); got != c.want {
			t.Errorf("inetCausa(%v,%v)=%q, quería %q", c.seen, c.fail, got, c.want)
		}
	}
}

// pingFalso responde según un mapa host → lista de resultados por intento.
type pingFalso struct {
	mu    sync.Mutex
	hacia map[string][]bool
	n     map[string]int
}

func (p *pingFalso) ping(h string, _ time.Duration) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.n[h]
	p.n[h]++
	r := p.hacia[h]
	if i < len(r) {
		return r[i]
	}
	return false
}

func nuevoFalso(m map[string][]bool) *pingFalso { return &pingFalso{hacia: m, n: map[string]int{}} }

func TestInternetRound(t *testing.T) {
	gw := "192.168.10.254"
	// con uno solo que conteste hay internet; sin re-prueba
	p := nuevoFalso(map[string][]bool{"9.9.9.9": {true}, gw: {true}})
	if ok, g := internetRound(p.ping, gw); !ok || !g {
		t.Errorf("uno responde: ok=%v gw=%v", ok, g)
	}
	if p.n["8.8.8.8"] != 1 {
		t.Errorf("no debía re-probar, intentos=%d", p.n["8.8.8.8"])
	}
	// los tres fallan, la re-prueba rescata (pérdida suelta)
	p = nuevoFalso(map[string][]bool{"1.1.1.1": {false, true}, gw: {true}})
	if ok, _ := internetRound(p.ping, gw); !ok {
		t.Error("la re-prueba debía rescatar la revisión")
	}
	// fallan los tres dos veces = falla; puerta contesta = proveedor
	p = nuevoFalso(map[string][]bool{gw: {true, true}})
	ok, g := internetRound(p.ping, gw)
	if ok || !g {
		t.Errorf("falla con puerta viva: ok=%v gw=%v", ok, g)
	}
	if p.n["9.9.9.9"] != 2 {
		t.Errorf("debía re-probar los tres, intentos=%d", p.n["9.9.9.9"])
	}
	// puerta muerta en ambos intentos
	p = nuevoFalso(nil)
	if ok, g := internetRound(p.ping, gw); ok || g {
		t.Errorf("todo muerto: ok=%v gw=%v", ok, g)
	}
	// puerta que contesta solo en la re-prueba cuenta como que contestó
	p = nuevoFalso(map[string][]bool{gw: {false, true}})
	if _, g := internetRound(p.ping, gw); !g {
		t.Error("la puerta contestó en la re-prueba")
	}
	// sin puerta conocida: no se pinguea
	p = nuevoFalso(nil)
	internetRound(p.ping, "")
	if len(p.n) != 3 {
		t.Errorf("solo debían revisarse 3 destinos, hubo %d", len(p.n))
	}
}

// Dos fallas seguidas = corte; la causa sale de la puerta durante todo el corte.
func TestInternetSampleCausa(t *testing.T) {
	s := &Store{inetInit: true}
	s.InternetSample(false, true, true) // primera falla, puerta viva
	if s.inetDown != 0 {
		t.Fatal("una sola falla no es corte")
	}
	s.InternetSample(false, true, true)
	if s.inetDown == 0 {
		t.Fatal("dos fallas deben abrir el corte")
	}
	s.InternetSample(false, false, true) // la puerta falla una vez
	if got := inetCausa(s.inetGwSeen, s.inetGwFail); got != "router o cable" {
		t.Errorf("causa=%q", got)
	}
	s.InternetSample(true, true, true)
	if s.inetDown != 0 {
		t.Error("debía cerrarse el corte")
	}
}
