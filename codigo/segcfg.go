package main

// Administración de segmentos (v2.2.0): agregar a mano, ocultar, ponerles nombre
// y fijar su puerta de enlace. Se guarda en SQLite (tabla meta, clave "segcfg").
//
// La clave de cada segmento es la misma que usa segOf: "10" (192.168.10.x) o
// "10.20.30" (otras redes).

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

type SegCfg struct {
	Seg      string `json:"seg"`
	Name     string `json:"name,omitempty"`
	Location string `json:"location,omitempty"` // ej. "Piso 3, área de Comisiones"
	Gateway  string `json:"gateway,omitempty"`  // puerta de enlace fijada a mano
	Manual   bool   `json:"manual,omitempty"`   // agregado a mano: se barre aunque no se oiga
	Hidden   bool   `json:"hidden,omitempty"`   // oculto: no se revisa, no alerta, no se muestra
}

var (
	segMu  sync.RWMutex
	segCfg = map[string]*SegCfg{}
)

// segKey normaliza lo que escribe el usuario: "130", "192.168.130", "192.168.130.0/24",
// "10.20.30" → clave de segmento ("130", "10.20.30"). "" si no es válido.
func segKey(in string) string {
	in = strings.TrimSpace(in)
	in = strings.TrimSuffix(in, "/24")
	p := strings.Split(in, ".")
	if len(p) == 4 {
		p = p[:3]
	}
	if len(p) == 1 {
		p = []string{"192", "168", p[0]}
	}
	if len(p) != 3 {
		return ""
	}
	ip := net.ParseIP(strings.Join(p, ".") + ".0").To4()
	if ip == nil || !ip.IsPrivate() {
		return ""
	}
	return segOf(ip.String())
}

// segPrefix: "130" → "192.168.130"; "10.20.30" → "10.20.30".
func segPrefix(k string) string {
	if !strings.Contains(k, ".") {
		return "192.168." + k
	}
	return k
}

func segHidden(k string) bool {
	segMu.RLock()
	defer segMu.RUnlock()
	c := segCfg[k]
	return c != nil && c.Hidden
}

func segName(k string) string {
	segMu.RLock()
	defer segMu.RUnlock()
	if c := segCfg[k]; c != nil {
		return c.Name
	}
	return ""
}

func segLocation(k string) string {
	segMu.RLock()
	defer segMu.RUnlock()
	if c := segCfg[k]; c != nil {
		return c.Location
	}
	return ""
}

func segGatewayFixed(k string) string {
	segMu.RLock()
	defer segMu.RUnlock()
	if c := segCfg[k]; c != nil {
		return c.Gateway
	}
	return ""
}

// manualSegments: prefijos agregados a mano (no ocultos), para barrerlos.
func manualSegments() []string {
	segMu.RLock()
	defer segMu.RUnlock()
	var out []string
	for k, c := range segCfg {
		if c.Manual && !c.Hidden {
			out = append(out, segPrefix(k))
		}
	}
	sort.Strings(out)
	return out
}

func (s *Store) loadSegCfg() {
	if s.db == nil {
		return
	}
	var list []SegCfg
	if json.Unmarshal([]byte(s.db.Meta("segcfg")), &list) != nil {
		return
	}
	segMu.Lock()
	for i := range list {
		c := list[i]
		segCfg[c.Seg] = &c
	}
	segMu.Unlock()
}

func (s *Store) saveSegCfg() {
	if s.db == nil {
		return
	}
	b, _ := json.Marshal(SegConfigList())
	s.db.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO meta(k,v) VALUES('segcfg',?)`, string(b))
		return err
	})
}

func SegConfigList() []SegCfg {
	segMu.RLock()
	defer segMu.RUnlock()
	out := make([]SegCfg, 0, len(segCfg))
	for _, c := range segCfg {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seg < out[j].Seg })
	return out
}

// SetSegCfg guarda la configuración de un segmento. Si queda vacía (sin nombre,
// puerta, ni marcas), se borra.
func (s *Store) SetSegCfg(c SegCfg) error {
	k := segKey(c.Seg)
	if k == "" {
		return fmt.Errorf("segmento inválido (ej. 130, 192.168.130 o 10.20.30)")
	}
	c.Seg, c.Name, c.Location = k, strings.TrimSpace(c.Name), strings.TrimSpace(c.Location)
	c.Gateway = strings.TrimSpace(c.Gateway)
	if c.Gateway != "" {
		ip := net.ParseIP(c.Gateway).To4()
		if ip == nil || segOf(ip.String()) != k {
			return fmt.Errorf("la puerta de enlace debe ser una IP de ese segmento (%s.x)", segPrefix(k))
		}
	}
	segMu.Lock()
	old := segCfg[k]
	if c.Name == "" && c.Location == "" && c.Gateway == "" && !c.Manual && !c.Hidden {
		delete(segCfg, k)
	} else {
		segCfg[k] = &c
	}
	segMu.Unlock()
	s.mu.Lock()
	if old == nil || old.Gateway != c.Gateway {
		delete(s.gws, k) // se vuelve a revisar con la puerta nueva
	}
	if c.Hidden {
		delete(s.alerts, k)
		delete(s.netSince, k)
	}
	s.mu.Unlock()
	s.saveSegCfg()
	return nil
}

func (s *Store) DeleteSegCfg(seg string) {
	k := segKey(seg)
	segMu.Lock()
	delete(segCfg, k)
	segMu.Unlock()
	s.mu.Lock()
	delete(s.gws, k)
	s.mu.Unlock()
	s.saveSegCfg()
}
