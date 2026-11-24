package main

import (
	"path/filepath"
	"testing"
)

func nuevoStoreTipo(t *testing.T) *Store {
	s := NewStore(filepath.Join(t.TempDir(), "datos.json"))
	s.Devs["aa:bb:cc:dd:ee:01"] = &Device{ID: "aa:bb:cc:dd:ee:01", MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.1.10"}
	return s
}

func TestKindManualNoSePisa(t *testing.T) {
	s := nuevoStoreTipo(t)
	id := "aa:bb:cc:dd:ee:01"
	k := "laptop"
	if err := s.UpdateDevice(id, "x", "", true, &k); err != nil {
		t.Fatal(err)
	}
	d, _ := s.Device(id)
	if d.Kind != "laptop" || d.KindManual != "laptop" {
		t.Fatalf("no se fijó: %+v", d.Kind)
	}
	s.SetIdentity(id, IDInfo{NetBIOS: "DESKTOP-1", Kind: "escritorio"})
	d, _ = s.Device(id)
	if d.Kind != "laptop" || d.NetBIOS != "DESKTOP-1" || d.Identified.IsZero() {
		t.Fatalf("SetIdentity pisó el tipo o no guardó pistas: kind=%s", d.Kind)
	}
	// ausente: no toca
	if err := s.UpdateDevice(id, "y", "", true, nil); err != nil {
		t.Fatal(err)
	}
	if d, _ = s.Device(id); d.KindManual != "laptop" {
		t.Fatal("kind ausente no debe tocar KindManual")
	}
	// auto: lo quita y fuerza re-identificar
	auto := "auto"
	if err := s.UpdateDevice(id, "y", "", true, &auto); err != nil {
		t.Fatal(err)
	}
	d, _ = s.Device(id)
	if d.KindManual != "" || !d.Identified.IsZero() {
		t.Fatal("auto debe quitar KindManual y poner Identified a cero")
	}
	s.SetIdentity(id, IDInfo{Kind: "escritorio"})
	if d, _ = s.Device(id); d.Kind != "escritorio" {
		t.Fatalf("tras auto debe tomar lo detectado: %s", d.Kind)
	}
}

func TestKindInvalidoRechazado(t *testing.T) {
	s := nuevoStoreTipo(t)
	id := "aa:bb:cc:dd:ee:01"
	mal := "nave-espacial"
	if err := s.UpdateDevice(id, "x", "", true, &mal); err != ErrTipoInvalido {
		t.Fatalf("esperaba ErrTipoInvalido, hubo %v", err)
	}
	if d, _ := s.Device(id); d.KindManual != "" || d.Name != "" {
		t.Fatal("un tipo inválido no debe cambiar nada")
	}
}

func TestGuessKindEscritorioLaptop(t *testing.T) {
	casos := []struct{ host, nb, want string }{
		{"DESKTOP-AB12", "", "escritorio"},
		{"", "DESKTOP-AB12", "escritorio"},
		{"LAPTOP-XY9", "", "laptop"},
		{"", "mi-notebook", "laptop"},
		{"PC-OFICINA", "", "windows"},
		{"WIN-123", "", "windows"},
	}
	for _, c := range casos {
		if got := guessKind("192.168.1.50", "aa:bb:cc:dd:ee:02", "", c.host, IDInfo{NetBIOS: c.nb}); got != c.want {
			t.Errorf("%q/%q: %s, esperaba %s", c.host, c.nb, got, c.want)
		}
	}
}
