package main

import (
	"path/filepath"
	"testing"
	"time"
)

func fijoCaido(s *Store, mac, ip string, now time.Time) {
	id := mac + "@" + ip
	s.Devs[id] = &Device{ID: id, MAC: mac, IP: ip, Kind: "red", Answers: true,
		upSinceStart: true, Fails: 3, failSince: now.Add(-time.Minute), LastSeen: now.Add(-2 * time.Minute)}
}

func TestSegmentoMismaIPDosMACNoAlerta(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "datos.json"))
	now := time.Now()
	fijoCaido(s, "aa:bb:cc:00:00:01", "192.168.10.20", now)
	fijoCaido(s, "aa:bb:cc:00:00:02", "192.168.10.20", now)
	s.EvalSegments(now)
	if len(s.alerts) != 0 {
		t.Fatalf("la misma IP con 2 MAC cuenta una vez, no debe alertar: %+v", s.alerts)
	}
}

func TestSegmentoDosIPsFijasDistintasAlertan(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "datos.json"))
	now := time.Now()
	fijoCaido(s, "aa:bb:cc:00:00:01", "192.168.10.20", now)
	fijoCaido(s, "aa:bb:cc:00:00:02", "192.168.10.21", now)
	s.EvalSegments(now)
	if len(s.alerts) != 1 {
		t.Fatalf("2 IPs fijas distintas caídas juntas deben alertar: %+v", s.alerts)
	}
	for _, a := range s.alerts {
		if a.Count != 2 {
			t.Fatalf("Count=%d, esperaba 2", a.Count)
		}
	}
}
