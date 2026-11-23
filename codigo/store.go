package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const historyLen = 120 // puntos de latencia guardados por equipo (~1 h)

const (
	bucketSecs = 30 * 60 // resumen cada 30 min (7 días = 336 puntos por equipo)
	bucketKeep = 7 * 24 * 3600 / bucketSecs
)

type Point struct {
	T  int64   `json:"t"`  // unix segundos
	Ms float64 `json:"ms"` // -1 = sin respuesta
}

// Bucket resume 15 minutos: [inicio unix, suma ms, máx ms, respondidos, perdidos]
type Bucket [5]float64

func addToBuckets(b []Bucket, now int64, ms float64) []Bucket {
	start := float64(now - now%bucketSecs)
	if len(b) == 0 || b[len(b)-1][0] != start {
		b = append(b, Bucket{start})
		if len(b) > bucketKeep {
			b = b[len(b)-bucketKeep:]
		}
	}
	k := &b[len(b)-1]
	if ms < 0 {
		k[4]++
	} else {
		k[1] += ms
		if ms > k[2] {
			k[2] = ms
		}
		k[3]++
	}
	return b
}

type Device struct {
	ID           string    `json:"id"`              // MAC, o MAC@IP para equipos de otros segmentos
	Via          string    `json:"via,omitempty"`   // "arp" = descubierto escuchando el cable
	Alias        bool      `json:"alias,omitempty"` // otra IP de un equipo que ya está en la lista (p. ej. el router)
	MAC          string    `json:"mac"`
	IP           string    `json:"ip"`
	Hostname     string    `json:"hostname"`
	Vendor       string    `json:"vendor"`
	Name         string    `json:"name"`
	Location     string    `json:"location,omitempty"` // ubicación escrita a mano (ej. "Piso 3, Contabilidad")
	Known        bool      `json:"known"`
	Online       bool      `json:"online"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	LatencyMs    float64   `json:"latencyMs"`
	ARPOnly      bool      `json:"arpOnly"` // no contesta ping; se mide por ARP
	History      []Point   `json:"history"`
	Buckets      []Bucket  `json:"buckets,omitempty"` // 7 días resumidos (no se manda en /api/devices)
	Fails        int       `json:"-"`
	checked      bool      // ya se revisó desde que arrancó el programa
	wentDown     bool      // estaba en línea y dejó de responder (para avisar "se desconectó")
	failSince    time.Time // primer chequeo fallido del corte actual
	heardAt      time.Time // última vez que se le escuchó en el cable (ARP propio) o en el escaneo
	upSinceStart bool      // ya respondió desde que arrancó el programa
	Answers      bool      `json:"answers"` // alguna vez contestó una revisión (si nunca, solo se le "escucha")

	// pistas para identificarlo
	NetBIOS    string    `json:"netbios,omitempty"`
	MDNS       string    `json:"mdns,omitempty"`
	Ports      []int     `json:"ports,omitempty"`
	WebTitle   string    `json:"webTitle,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Identified time.Time `json:"identified"`

	// salud (calculada a partir del historial de pings)
	Drops    []int64 `json:"drops,omitempty"` // momentos (unix) en que se cayó
	Loss     float64 `json:"loss"`            // % de pings perdidos en el historial (~1 h)
	Jitter   float64 `json:"jitter"`          // variación promedio de latencia (ms)
	Drops24h int     `json:"drops24h"`
	Health   string  `json:"health"` // normal, inestable, problema, caido
}

const (
	gapMs           = -2              // punto de "desconectado" (hueco en la gráfica, no pérdida)
	disconnectAfter = 3 * time.Minute // sin responder nada por 3 min = se desconectó
	disconnectFails = 6               // 6 chequeos de 30 s
)

// Equipos que deben estar siempre prendidos: si dejan de responder es caída, no
// "se desconectó" (a un router o una impresora nadie los apaga y se va).
var fixedKinds = map[string]bool{"router": true, "impresora": true, "camara": true, "nas": true, "red": true, "telefono-ip": true}

// Las IPs extra de un mismo equipo (alias) no cuentan como fijos ni avisan: al
// router real lo vigila su IP principal.
// Solo cuenta como fijo si alguna vez contestó: de uno que nunca contesta no se
// puede afirmar que "cayó".
func isFixed(d *Device) bool { return fixedKinds[d.Kind] && !d.Alias && d.Answers }

func fmtDur(dur time.Duration) string {
	m := int(dur.Minutes())
	switch {
	case m < 1:
		return "menos de 1 min"
	case m >= 60:
		return fmt.Sprintf("%d h %d min", m/60, m%60)
	}
	return fmt.Sprintf("%d min", m)
}

// markGap convierte en "desconectado" los puntos perdidos del corte actual:
// resultó que no era falla, se desconectó (también los descuenta del resumen).
func markGap(d *Device) {
	for i := len(d.History) - 1; i >= 0 && d.History[i].Ms == -1; i-- {
		d.History[i].Ms = gapMs
		start := float64(d.History[i].T - d.History[i].T%bucketSecs)
		for k := len(d.Buckets) - 1; k >= 0; k-- {
			if d.Buckets[k][0] == start {
				if d.Buckets[k][4] > 0 {
					d.Buckets[k][4]--
				}
				break
			}
		}
	}
}

// cameBackLocked: el equipo volvió a responder. Decide si fue un corte (falla)
// o una desconexión (normal) y lo anota en Eventos.
func (s *Store) cameBackLocked(d *Device, now time.Time, prevFails int) {
	if d.Online || !d.checked || d.Alias {
		return
	}
	away := now.Sub(d.LastSeen)
	switch {
	case isFixed(d):
		s.addEventLocked("conectado", fmt.Sprintf("%s se volvió a conectar (estuvo desconectado %s)", label(d), fmtDur(away)), d)
	case prevFails >= disconnectFails || away >= disconnectAfter:
		s.addEventLocked("conectado", fmt.Sprintf("%s se volvió a conectar (estuvo desconectado %s)", label(d), fmtDur(away)), d)
	default:
		// volvió antes de 3 min: eso sí es un corte (intermitencia)
		d.Drops = append(d.Drops, now.Unix())
		for len(d.Drops) > 0 && now.Unix()-d.Drops[0] > 7*86400 {
			d.Drops = d.Drops[1:]
		}
		s.addEventLocked("corte", fmt.Sprintf("%s tuvo un corte de %s", label(d), fmtDur(away)), d)
	}
}

// calcHealth resume el historial de un equipo en un semáforo.
func calcHealth(d *Device, now time.Time) {
	// Pérdidas "sueltas" = intermitencia. Un corte seguido de 3 min o más es una
	// desconexión (lo apagaron, se suspendió, quitaron el cable): ya se cuenta
	// como caída, y si el equipo volvió y está estable no es una falla.
	const longRun = 6 // 6 chequeos de 30 s = 3 min
	lost, valid, run := 0, 0, 0
	closeRun := func() {
		if run > 0 && run < longRun {
			lost += run
		}
		run = 0
	}
	var prev, sum float64
	n := 0
	for _, p := range d.History {
		if p.Ms <= gapMs { // desconectado: no cuenta ni como respuesta ni como pérdida
			closeRun()
			continue
		}
		valid++
		if p.Ms < 0 {
			run++
			continue
		}
		closeRun()
		if p.Ms > 0 { // 0 = respondió solo por ARP, sin latencia medida
			if prev > 0 {
				diff := p.Ms - prev
				if diff < 0 {
					diff = -diff
				}
				sum += diff
				n++
			}
			prev = p.Ms
		}
	}
	closeRun()
	d.Loss, d.Jitter = 0, 0
	if valid > 0 {
		d.Loss = float64(lost) * 100 / float64(valid)
	}
	if n > 0 {
		d.Jitter = sum / float64(n)
	}
	d.Drops24h = 0
	for _, t := range d.Drops {
		if now.Unix()-t < 86400 {
			d.Drops24h++
		}
	}
	switch {
	case !d.Online && !d.upSinceStart && d.Fails < disconnectFails:
		d.Health = "pendiente" // recién arrancó el programa: aún no se sabe, no cuenta
	case !d.Online && !d.Answers:
		d.Health = "desconectado" // nunca contesta y ya no se le escucha: no se puede afirmar falla
	case !d.Online:
		// Solo tres estados para el usuario: conectado, sin internet, desconectado.
		// Un equipo que no responde está desconectado (no existe "caído").
		d.Health = "desconectado"
	// un solo ping perdido no basta para marcar al equipo (pide un mínimo de pérdidas)
	// pérdidas: se califica solo con 10 min de datos o más (20 revisiones); con
	// menos, 2 pings perdidos de 10 parecerían 20 % y sería una falsa alarma
	case valid >= 20 && ((lost >= 4 && d.Loss >= 15) || d.Drops24h >= 5):
		d.Health = "problema"
	case d.Drops24h >= 5:
		d.Health = "problema"
	case valid >= 20 && ((lost >= 2 && d.Loss >= 3) || (n >= 10 && d.Jitter >= 30)), d.Drops24h >= 3:
		d.Health = "inestable"
	default:
		d.Health = "normal"
	}
}

type Target struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"` // 0 = ping ICMP, >0 = chequeo TCP
	Online    bool      `json:"online"`
	LatencyMs float64   `json:"latencyMs"`
	LastCheck time.Time `json:"lastCheck"`
	Uptime    float64   `json:"uptime"` // % sobre el historial
	History   []Point   `json:"history"`
}

type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"` // new, offline, online, info
	Message string    `json:"message"`
	Seg     string    `json:"seg,omitempty"` // segmento del evento ("" = general)
}

type Store struct {
	mu            sync.RWMutex
	path          string
	Devs          map[string]*Device                    `json:"devices"`
	Tgts          []*Target                             `json:"targets"`
	Evts          []Event                               `json:"events"`
	Ver           string                                `json:"version"` // versión que guardó los datos
	Subnet        string                                `json:"subnet"`  // red vigilada (para detectar cambios)
	alerts        map[string]*segAlert                  // segmentos caídos completos (en memoria)
	segNet        map[string]string                     // internet por segmento: ok, sin, ?
	segGW         map[string]string                     // puerta de enlace por segmento
	netSince      map[string]time.Time                  // desde cuándo un segmento está sin internet
	gwVotes       map[string]map[string]map[string]bool // segmento → IP preguntada → quién preguntó
	gws           map[string]*gwState                   // puerta de enlace de cada segmento y su estado
	netLast       map[string]string                     // último internet conocido por segmento (ok/sin)
	probes        map[string]*probeState                // opción A: internet probado desde cada segmento
	proxyARP      map[string]bool                       // "seg|mac" que contesta por todo el segmento
	gwWarn        map[string]string                     // segmento → puerta de las PCs distinta a la probada (ya avisado)
	inetDown      int64                                 // inicio del corte de internet en curso (0 = hay internet)
	inetInit      bool                                  // ya se cerraron los cortes que quedaron abiertos al apagar
	inetFails     int                                   // revisiones rápidas seguidas sin internet
	inetFirstFail int64                                 // hora de la primera de esas fallas
	db            *DB                                   // SQLite (si no se pudo abrir, se usa el JSON de antes)
	baselineUntil time.Time                             // fin del inventario inicial
	dirty         bool
}

func NewStore(path string) *Store {
	s := &Store{path: path, Devs: map[string]*Device{}}
	go func() {
		// estado de los equipos cada 10 min (en SQLite solo se escriben filas, no todo)
		for range time.Tick(10 * time.Minute) {
			s.Save(false)
		}
	}()
	go func() {
		// resumen por segmento cada 5 min: la base para pronósticos y reportes
		for range time.Tick(5 * time.Minute) {
			s.recordSegments()
		}
	}()
	return s
}

func dbPathFor(p string) string { return strings.TrimSuffix(p, filepath.Ext(p)) + ".db" }

func (s *Store) Load() error {
	db, err := OpenDB(dbPathFor(s.path))
	if err != nil {
		log.Printf("aviso: no se pudo abrir SQLite (%v); se usa %s", err, s.path)
	} else {
		s.db = db
		if db.Meta("version") != "" {
			return s.loadDB()
		}
		// base nueva: se empieza DE CERO con un inventario inicial de la red.
		// El JSON viejo se guarda como respaldo, no se borra.
		if _, err := os.Stat(s.path); err == nil {
			os.Rename(s.path, strings.TrimSuffix(s.path, ".json")+".anterior.json")
			log.Printf("se empieza de cero; respaldo del archivo anterior: %s", strings.TrimSuffix(s.path, ".json")+".anterior.json")
		}
		s.mu.Lock()
		s.seedTargets()
		s.Ver = version
		s.baselineUntil = time.Now().Add(baselineFor)
		s.mu.Unlock()
		s.Save(true)
		return nil
	}
	return s.loadJSON() // sin SQLite: como antes
}

// Inventario inicial: los primeros 20 min registra en silencio todo lo que hay
// (sin un evento "Nuevo" por cada uno). Después, lo que aparezca sí es nuevo.
const baselineFor = 20 * time.Minute

func (s *Store) inBaseline() bool {
	return !s.baselineUntil.IsZero() && time.Now().Before(s.baselineUntil)
}

// endBaseline deja el evento resumen al terminar el inventario inicial.
func (s *Store) endBaselineLocked() {
	if s.baselineUntil.IsZero() || time.Now().Before(s.baselineUntil) {
		return
	}
	s.baselineUntil = time.Time{}
	s.addEventLocked("info", fmt.Sprintf("Inventario inicial: %d equipos registrados. Desde ahora, lo que aparezca se marca como nuevo", len(s.Devs)))
	if s.db != nil {
		s.db.Do(func(tx *sql.Tx) error { _, err := tx.Exec(`DELETE FROM meta WHERE k='baseline_until'`); return err })
	}
}

func (s *Store) loadDB() error {
	devs, err := s.db.LoadDevices()
	if err != nil {
		return err
	}
	buckets := s.db.LoadBuckets(time.Now().Add(-7 * 24 * time.Hour).Unix())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Devs = devs
	s.Tgts = s.db.LoadTargets()
	s.Evts = s.db.LoadEvents(300)
	s.Subnet = s.db.Meta("subnet")
	s.loadSegCfg()
	s.Ver = s.db.Meta("version") // si no, se tomaría como datos viejos y se limpiarían
	if v := s.db.Meta("baseline_until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			s.baselineUntil = t
		}
	}
	for k, d := range s.Devs {
		d.Buckets = buckets[k]
	}
	s.prepareLocked()
	log.Printf("datos cargados de SQLite: %d equipos", len(s.Devs))
	return nil
}

func (s *Store) loadJSON() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.seedTargets()
			s.Ver = version
			return nil
		}
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := json.Unmarshal(b, s); err != nil {
		return err
	}
	s.prepareLocked()
	return nil
}

// prepareLocked deja los datos recién cargados listos para usarse.
func (s *Store) prepareLocked() {
	if s.Devs == nil {
		s.Devs = map[string]*Device{}
	}
	for k, d := range s.Devs {
		d.ID = k
		d.Online = false
		d.Identified = time.Time{} // al arrancar se vuelven a buscar pistas
		if v := vendorOf(d.MAC); v != "" {
			d.Vendor = v
		}
	}
	if s.Ver == "" {
		// datos de antes de la 1.2: eventos de la red anterior e historial con
		// falsas pérdidas (equipos que no contestan ping) → se empieza limpio
		s.Evts = nil
		for _, d := range s.Devs {
			d.History, d.Drops = nil, nil
		}
	}
	if s.Ver == "1.2.0" {
		s.Evts = nil // la 1.2.0 llenaba eventos con "volvió" al arrancar
	}
	if strings.HasPrefix(s.Ver, "1.9.") && s.Ver < "1.9.4" {
		// hasta la 1.9.3, los equipos que no contestan la revisión pero se escuchan en
		// la red (routers Ubiquiti en otros segmentos) quedaron con pérdidas falsas
		for _, d := range s.Devs {
			measured, heard := false, false
			for _, p := range d.History {
				measured = measured || p.Ms > 0
				heard = heard || p.Ms == 0
			}
			if measured || !heard {
				continue
			}
			for i := range d.History {
				if d.History[i].Ms == -1 {
					d.History[i].Ms = 0
				}
			}
			for i := range d.Buckets {
				d.Buckets[i][3] += d.Buckets[i][4]
				d.Buckets[i][4] = 0
			}
			d.Drops = nil
		}
	}
	s.Ver = version
	s.dirty = true
}

func (s *Store) seedTargets() {
	s.Tgts = []*Target{
		{ID: newID(), Name: "Google DNS", Host: "8.8.8.8"},
		{ID: newID(), Name: "Cloudflare DNS", Host: "1.1.1.1"},
	}
	s.dirty = true
}

// Save guarda el estado. En SQLite se escriben filas (equipos y el resumen de
// 30 min en curso); el historial de 1 h solo con full (al detener el servicio).
func (s *Store) Save(full bool) {
	s.mu.Lock()
	s.endBaselineLocked()
	if s.db == nil { // sin SQLite: JSON como antes
		if !s.dirty && !full {
			s.mu.Unlock()
			return
		}
		b, err := json.Marshal(s)
		s.dirty = false
		s.mu.Unlock()
		if err == nil && os.WriteFile(s.path+".tmp", b, 0644) == nil {
			os.Rename(s.path+".tmp", s.path)
		}
		return
	}
	devs := make([]Device, 0, len(s.Devs))
	for _, d := range s.Devs {
		c := *d
		if len(c.Buckets) > 0 {
			s.db.PutBucket(c.ID, c.Buckets[len(c.Buckets)-1]) // el de 30 min en curso
		}
		c.Buckets = nil
		if !full {
			c.History = nil
		}
		devs = append(devs, c)
	}
	tgts := make([]Target, 0, len(s.Tgts))
	for _, t := range s.Tgts {
		tgts = append(tgts, *t)
	}
	meta := map[string]string{"version": version, "subnet": s.Subnet}
	if !s.baselineUntil.IsZero() {
		meta["baseline_until"] = s.baselineUntil.Format(time.RFC3339)
	}
	s.dirty = false
	s.mu.Unlock()
	s.db.SaveState(devs, tgts, meta)
}

// Close guarda todo (con el historial de 1 h) y espera a que se escriba.
func (s *Store) Close() {
	s.Save(true)
	if s.db != nil {
		s.db.Flush()
	}
}

func (s *Store) MarkDirty() { s.mu.Lock(); s.dirty = true; s.mu.Unlock() }

// bucketLocked suma un chequeo al resumen de 30 min; cuando empieza uno nuevo,
// el anterior (ya cerrado) se guarda en SQLite.
func (s *Store) bucketLocked(d *Device, now int64, ms float64) {
	var closed *Bucket
	if n := len(d.Buckets); n > 0 && d.Buckets[n-1][0] != float64(now-now%bucketSecs) {
		b := d.Buckets[n-1] // el de 30 min anterior terminó
		closed = &b
	}
	d.Buckets = addToBuckets(d.Buckets, now, ms)
	if s.db != nil && closed != nil {
		s.db.PutBucket(d.ID, *closed)
	}
}

// recordSegments guarda el resumen de cada segmento (cada 5 min).
func (s *Store) recordSegments() {
	if s.db == nil {
		return
	}
	type acc struct {
		lat, loss float64
		nl, n     int
	}
	agg := map[string]*acc{}
	for _, d := range s.DeviceList() {
		if d.Health == "desconectado" {
			continue
		}
		k := segOf(d.IP)
		a := agg[k]
		if a == nil {
			a = &acc{}
			agg[k] = a
		}
		a.loss += d.Loss
		a.n++
		if d.Online && d.LatencyMs > 0 {
			a.lat += d.LatencyMs
			a.nl++
		}
	}
	t := time.Now().Unix()
	t -= t % 300
	for _, g := range s.Segments() {
		var avg, loss float64
		if a := agg[g.Seg]; a != nil {
			if a.nl > 0 {
				avg = a.lat / float64(a.nl)
			}
			if a.n > 0 {
				loss = a.loss / float64(a.n)
			}
		}
		s.db.PutSegSample(t, g, avg, loss)
	}
}

func newID() string { return fmt.Sprintf("%x", time.Now().UnixNano()) }

func pushPoint(h []Point, p Point) []Point {
	h = append(h, p)
	if len(h) > historyLen {
		h = h[len(h)-historyLen:]
	}
	return h
}

// addEventLocked anota un evento: los últimos 300 en memoria (para la página) y
// todos en SQLite (1 año). Con d, se guarda también su segmento y equipo.
func (s *Store) addEventLocked(kind, msg string, d ...*Device) {
	seg, dev := "", ""
	if len(d) > 0 && d[0] != nil {
		seg, dev = segOf(d[0].IP), d[0].ID
		if segHidden(seg) {
			return // segmento oculto: sin eventos
		}
	}
	e := Event{Time: time.Now(), Kind: kind, Message: msg, Seg: seg}
	s.Evts = append(s.Evts, e)
	if len(s.Evts) > 300 {
		s.Evts = s.Evts[len(s.Evts)-300:]
	}
	s.dirty = true
	if s.db != nil {
		s.db.AddEvent(e, seg, dev)
	}
}

func (s *Store) segEventLocked(kind, seg, msg string) {
	if segHidden(seg) {
		return
	}
	e := Event{Time: time.Now(), Kind: kind, Message: msg, Seg: seg}
	s.Evts = append(s.Evts, e)
	if len(s.Evts) > 300 {
		s.Evts = s.Evts[len(s.Evts)-300:]
	}
	if s.db != nil {
		s.db.AddEvent(e, seg, "")
	}
}

func (s *Store) AddEvent(kind, msg string) {
	s.mu.Lock()
	s.addEventLocked(kind, msg)
	s.mu.Unlock()
}

func label(d *Device) string {
	if d.Name != "" {
		return d.Name
	}
	if d.Hostname != "" {
		return d.Hostname
	}
	return d.IP
}

// backMsg: "X volvió después de 11 min sin responder" (LastSeen = última respuesta).
func backMsg(d *Device, now time.Time) string {
	if d.LastSeen.IsZero() {
		return fmt.Sprintf("%s volvió a estar en línea", label(d))
	}
	m := int(now.Sub(d.LastSeen).Minutes())
	dur := fmt.Sprintf("%d min", m)
	if m >= 60 {
		dur = fmt.Sprintf("%d h %d min", m/60, m%60)
	}
	if m < 1 {
		dur = "menos de 1 min"
	}
	return fmt.Sprintf("%s volvió después de %s sin responder", label(d), dur)
}

// SeenDevice registra un equipo encontrado en el escaneo de la red principal.
func (s *Store) SeenDevice(mac, ip, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seenLocked(mac, mac, ip, host, "")
}

// SeenPassive registra un equipo que "habló" por ARP en el cable. Si es de otro
// segmento se guarda como entrada aparte (MAC@IP): un mismo equipo, como el
// router, puede tener una IP en cada segmento.
func (s *Store) SeenPassive(mac, ip string, main *net.IPNet) {
	if isProbeIP(ip) { // la propia Pi en otro segmento (opción A)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if main != nil && main.Contains(net.ParseIP(ip)) {
		s.seenLocked(mac, mac, ip, "", "") // segmento propio: igual que los demás
		return
	}
	if _, ya := s.Devs[mac+"@"+ip]; !ya && s.proxyARP[segOf(ip)+"|"+mac] {
		return // aparato que contesta por todas las IPs del segmento (proxy ARP)
	}
	s.seenLocked(mac+"@"+ip, mac, ip, "", "arp")
}

// proxyMinIPs: una misma MAC con tantas IPs en UN segmento no son equipos, es un
// aparato contestando por todos (proxy ARP). En el 165 un 3Com dio 119 "equipos"
// que al apagarse dejaron una alerta de segmento pegada.
const proxyMinIPs = 8

// pruneGhostsLocked quita equipos fantasma: las IPs de prueba de la Pi y los
// "equipos" de un proxy ARP.
func (s *Store) pruneGhostsLocked() {
	if s.proxyARP == nil {
		s.proxyARP = map[string]bool{}
	}
	n := map[string]int{}
	for _, d := range s.Devs {
		if d.Via == "arp" {
			n[segOf(d.IP)+"|"+d.MAC]++
		}
	}
	var gone []string
	for k, d := range s.Devs {
		pk := segOf(d.IP) + "|" + d.MAC
		switch {
		case isProbeIP(d.IP):
		case d.Via == "arp" && n[pk] >= proxyMinIPs && d.Name == "":
			if !s.proxyARP[pk] {
				s.proxyARP[pk] = true
				s.addEventLocked("info", fmt.Sprintf("%s: el aparato %s (%s) contesta por %d IPs (proxy ARP); no se cuentan como equipos", segLabel(segOf(d.IP)), d.MAC, d.Vendor, n[pk]))
			}
		default:
			continue
		}
		delete(s.Devs, k)
		gone = append(gone, k)
	}
	if len(gone) > 0 {
		s.dropFromDB(gone)
		s.dirty = true
	}
}

func (s *Store) seenLocked(key, mac, ip, host, via string) {
	now := time.Now()
	d, ok := s.Devs[key]
	if !ok {
		d = &Device{ID: key, MAC: mac, IP: ip, Hostname: host, Vendor: vendorOf(mac), FirstSeen: now, Via: via}
		s.Devs[key] = d
		if !s.inBaseline() { // en el inventario inicial se registra en silencio
			s.addEventLocked("new", fmt.Sprintf("Equipo nuevo: %s (%s, %s)", label(d), ip, mac), d)
		}
	}
	if d.IP != ip {
		s.addEventLocked("info", fmt.Sprintf("%s cambió de IP %s → %s", label(d), d.IP, ip), d)
		d.IP = ip
	}
	if host != "" {
		d.Hostname = host
	}
	if v := vendorOf(mac); v != "" {
		d.Vendor = v
	}
	if ok {
		s.cameBackLocked(d, now, d.Fails) // al arrancar no avisa (checked = false)
	}
	d.checked, d.wentDown, d.upSinceStart = true, false, true
	d.heardAt = now
	d.Online = true
	d.Fails = 0
	d.LastSeen = now
	s.dirty = true
}

// DevicePing registra el resultado de un ping a un equipo conocido.
func (s *Store) DevicePing(mac string, ms float64, ok, viaARP bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.Devs[mac]
	if d == nil {
		return
	}
	now := time.Now()
	if ok && ms != 0 {
		d.Answers = true // contestó de verdad (ping o ARP con latencia)
	}
	// no contestó, pero se le escuchó hablar en el cable hace poco: está presente.
	// A los que NUNCA contestan (routers en otros segmentos) se les da más margen,
	// porque solo hablan cada tantos minutos.
	window := 90 * time.Second
	if !d.Answers {
		window = 30 * time.Minute
	}
	if !ok && now.Sub(d.heardAt) < window {
		ok, ms, viaARP = true, 0, true
	}
	if ok {
		d.upSinceStart = true
		s.cameBackLocked(d, now, d.Fails)
		d.checked, d.wentDown, d.failSince = true, false, time.Time{}
		d.Online, d.Fails, d.LastSeen, d.LatencyMs, d.ARPOnly = true, 0, now, ms, viaARP
		d.History = pushPoint(d.History, Point{now.Unix(), ms})
		s.bucketLocked(d, now.Unix(), ms)
	} else {
		d.checked = true
		d.Fails++
		if d.Fails == 1 {
			d.failSince = now
		}
		fixed := isFixed(d)
		switch {
		case !d.upSinceStart:
			// recién arrancó y aún no responde: no es pérdida, es "todavía sin datos"
			d.History = pushPoint(d.History, Point{now.Unix(), gapMs})
		case !fixed && d.Fails >= disconnectFails:
			// ya son 3 min sin responder nada: se desconectó (hueco, no pérdida)
			if d.Fails == disconnectFails {
				markGap(d)
				if d.wentDown && !d.Alias {
					s.addEventLocked("desconectado", fmt.Sprintf("%s se desconectó", label(d)), d)
				}
			}
			d.History = pushPoint(d.History, Point{now.Unix(), gapMs})
		default:
			d.History = pushPoint(d.History, Point{now.Unix(), -1})
			s.bucketLocked(d, now.Unix(), -1)
		}
		if d.Online && d.Fails >= 3 && d.upSinceStart {
			d.Online, d.wentDown = false, true
			if fixed { // router, impresora…: dejar de responder sí es caída
				d.Drops = append(d.Drops, now.Unix())
				for len(d.Drops) > 0 && now.Unix()-d.Drops[0] > 7*86400 {
					d.Drops = d.Drops[1:] // conserva 7 días
				}
				s.addEventLocked("desconectado", fmt.Sprintf("%s (%s) se desconectó", label(d), d.IP), d)
			}
		}
	}
	s.dirty = true
}

func (s *Store) DeviceList() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Device, 0, len(s.Devs))
	now := time.Now()
	for _, d := range s.Devs {
		c := *d
		c.Buckets = nil // el historial largo se pide aparte (/api/history)
		calcHealth(&c, now)
		out = append(out, c)
	}
	return out
}

// OtherSegments devuelve los segmentos /24 vistos en el cable fuera de la red
// principal (para barrerlos por ARP). No incluye 169.254 (equipos sin IP).
func (s *Store) OtherSegments(main *net.IPNet) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for _, p := range manualSegments() { // agregados a mano: siempre se barren
		ip := net.ParseIP(p + ".0").To4()
		if !seen[p] && ip != nil && (main == nil || !main.Contains(ip)) {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, d := range s.Devs {
		ip := net.ParseIP(d.IP).To4()
		if d.Via != "arp" || ip == nil || !ip.IsPrivate() || (main != nil && main.Contains(ip)) || segHidden(segOf(d.IP)) {
			continue
		}
		p := fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2])
		if !seen[p] && len(out) < 64 { // ~1.3 s por segmento: 42 segmentos < 1 min
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// HistoryPoint es un punto de la gráfica grande.
type HistoryPoint struct {
	T    int64   `json:"t"`
	Avg  float64 `json:"avg"` // -1 = no respondió en todo el periodo
	Max  float64 `json:"max"`
	Loss float64 `json:"loss"` // % perdidos en el periodo
}

// History devuelve la gráfica de un equipo: "1h" (cada 30 s), "24h" o "7d" (cada 15 min).
func (s *Store) History(mac, rng string) []HistoryPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.Devs[mac]
	if d == nil {
		return nil
	}
	out := []HistoryPoint{}
	if rng == "1h" {
		for _, p := range d.History {
			hp := HistoryPoint{T: p.T, Avg: p.Ms, Max: p.Ms}
			if p.Ms == -1 { // perdido (rojo); -2 = desconectado (hueco, sin rojo)
				hp.Loss = 100
			}
			out = append(out, hp)
		}
		return out
	}
	since := time.Now().Unix() - 24*3600
	if rng == "7d" {
		since = time.Now().Unix() - 7*24*3600
	}
	for _, b := range d.Buckets {
		if int64(b[0]) < since {
			continue
		}
		hp := HistoryPoint{T: int64(b[0]), Avg: -1, Max: b[2]}
		if b[3] > 0 {
			hp.Avg = b[1] / b[3]
		}
		if tot := b[3] + b[4]; tot > 0 {
			hp.Loss = b[4] * 100 / tot
		}
		out = append(out, hp)
	}
	return out
}

// NeedIdentify devuelve los equipos sin identificar o con datos de más de 6 h.
func (s *Store) NeedIdentify() []Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Device
	for _, d := range s.Devs {
		if d.Online && time.Since(d.Identified) > 6*time.Hour {
			out = append(out, *d)
		}
	}
	return out
}

func (s *Store) SetIdentity(mac string, i IDInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.Devs[mac]
	if d == nil {
		return
	}
	d.NetBIOS, d.MDNS, d.Ports, d.WebTitle, d.Kind = i.NetBIOS, i.MDNS, i.Ports, i.WebTitle, i.Kind
	d.Identified = time.Now()
	if d.Hostname == "" {
		if i.NetBIOS != "" {
			d.Hostname = i.NetBIOS
		} else if i.MDNS != "" {
			d.Hostname = i.MDNS
		}
	}
	s.dirty = true
}

func (s *Store) Device(mac string) (Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.Devs[mac]
	if d == nil {
		return Device{}, false
	}
	return *d, true
}

// segOf: "192.168.10.5" → "10"; "169.254.x.x" → "169.254"; otra → "10.0.3".
func segOf(ip string) string {
	p := strings.Split(ip, ".")
	if len(p) != 4 {
		return ip
	}
	if p[0] == "169" && p[1] == "254" {
		return "169.254"
	}
	if p[0] == "192" && p[1] == "168" {
		return p[2]
	}
	return p[0] + "." + p[1] + "." + p[2]
}

// Devices devuelve los equipos; con seg, solo los de ese segmento. Sin historial
// (lite) pesa mucho menos: se usa para buscar entre todos los segmentos.
func (s *Store) Devices(seg string, withHistory bool) []Device {
	all := s.DeviceList()
	out := all[:0]
	for _, d := range all {
		if seg != "" && segOf(d.IP) != seg {
			continue
		}
		if !withHistory {
			d.History = nil
		}
		d.Drops = nil
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

var kindLabel = map[string]string{
	"router": "router puerta de enlace", "raspberry": "raspberry pi", "impresora": "impresora",
	"camara": "camara cámara ip", "telefono-ip": "telefono teléfono ip", "iphone": "iphone ipad",
	"celular": "celular", "tv": "tv chromecast", "nas": "nas almacenamiento", "red": "equipo de red",
	"windows": "pc windows", "mac": "mac", "linux": "linux servidor", "iot": "iot inteligente",
	"virtual": "maquina virtual", "pc": "computadora pc",
}

var healthRank = map[string]int{"caido": 0, "problema": 1, "inestable": 2, "normal": 3, "pendiente": 4, "desconectado": 5}

func isIdentified(d *Device) bool {
	return d.Known || d.Name != "" || d.Hostname != "" || d.NetBIOS != "" || d.MDNS != "" ||
		(d.Vendor != "" && d.Vendor != "MAC privada (aleatoria)")
}

// Query filtra y ordena en la Pi (no en el navegador):
// f = "" conectados | ok con internet | noinet sin internet | nd internet desconocido |
// pend revisando | unk sin nombre | gone desconectados | all todos.
func (s *Store) Query(seg, q, f string, withHistory bool, limit int) []Device {
	q = strings.ToLower(strings.TrimSpace(q))
	s.mu.RLock()
	nets := s.segNet
	s.mu.RUnlock()
	noNet := func(d *Device) bool { return d.Online && nets[segOf(d.IP)] == "sin" }
	all := s.DeviceList()
	out := all[:0]
	for _, d := range all {
		if (seg != "" && segOf(d.IP) != seg) || segHidden(segOf(d.IP)) {
			continue
		}
		gone := d.Health == "desconectado"
		switch f {
		case "gone":
			if !gone {
				continue
			}
		case "all":
		default:
			if gone {
				continue
			}
		}
		if (f == "noinet" || f == "bad") && !noNet(&d) {
			continue
		}
		if f == "ok" && !(d.Online && nets[segOf(d.IP)] == "ok") {
			continue
		}
		if f == "nd" && !(d.Online && nets[segOf(d.IP)] != "ok" && nets[segOf(d.IP)] != "sin") {
			continue
		}
		if f == "pend" && d.Health != "pendiente" {
			continue
		}
		if f == "unk" && isIdentified(&d) {
			continue
		}
		if q != "" {
			hay := strings.ToLower(strings.Join([]string{d.IP, d.MAC, d.Name, d.Location, d.Hostname, d.Vendor, d.NetBIOS, d.MDNS, kindLabel[d.Kind]}, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		if !withHistory {
			d.History = nil
		}
		d.Drops = nil
		out = append(out, d)
	}
	// conectados primero, luego revisando, luego desconectados; dentro, por IP
	rank := func(d *Device) int {
		switch {
		case d.Online:
			return 0
		case d.Health == "pendiente":
			return 1
		}
		return 2
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := rank(&out[i]), rank(&out[j]); ri != rj {
			return ri < rj
		}
		return ipLess(out[i].IP, out[j].IP)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ---------- detector de fallas por segmento ----------

type segAlert struct {
	Since time.Time
	Count int      // equipos que cayeron a la vez
	Keys  []string // cuáles (si ya no existen, la alerta no puede quedarse pegada)
}

// failedKeysLocked: equipos de un segmento que están fallando desde "since" (±2 min).
func (s *Store) failedKeysLocked(seg string, since time.Time) []string {
	var ks []string
	for k, d := range s.Devs {
		if segOf(d.IP) == seg && !d.failSince.IsZero() && d.failSince.Sub(since) <= 2*time.Minute {
			ks = append(ks, k)
		}
	}
	return ks
}

// EvalSegments se corre después de cada ronda de chequeos. Si casi todos los
// equipos activos de un segmento dejan de responder EN EL MISMO MOMENTO (2 min),
// es falla del segmento (switch, cable o router), no gente apagando sus equipos.
func (s *Store) EvalSegments(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.alerts == nil {
		s.alerts = map[string]*segAlert{}
	}
	s.endBaselineLocked()
	s.pruneGhostsLocked()
	s.evalSegNetLocked(now)
	// alias: misma MAC con varias IPs (el router tiene una en cada segmento). Se
	// queda como principal la entrada de la red propia o, si no hay, la primera.
	first := map[string]string{}
	for k, d := range s.Devs {
		if f, ok := first[d.MAC]; !ok || k < f {
			first[d.MAC] = k
		}
	}
	for k, d := range s.Devs {
		_, own := s.Devs[d.MAC]
		d.Alias = k != d.MAC && (own || first[d.MAC] != k)
	}
	type acc struct {
		active, failing, online int
		first, last             time.Time
		fActive, fFailing       int // equipos fijos (impresoras, router…)
		fFirst, fLast           time.Time
	}
	g := map[string]*acc{}
	counted := map[string]bool{} // un aparato cuenta una vez por segmento aunque tenga varias IPs
	for _, d := range s.Devs {
		k := segOf(d.IP)
		if counted[k+"|"+d.MAC] {
			continue
		}
		counted[k+"|"+d.MAC] = true
		a := g[k]
		if a == nil {
			a = &acc{}
			g[k] = a
		}
		if d.Online {
			a.online++
		}
		failing := !d.failSince.IsZero() && d.Fails >= 2
		// activo = en línea, o estaba en línea hasta hace poco y está fallando ahora
		// (solo si ya respondió desde que arrancó: al reiniciar no hay falsas alertas)
		if d.Online || (failing && d.upSinceStart && now.Sub(d.LastSeen) < 15*time.Minute) {
			a.active++
		}
		recent := failing && d.upSinceStart && now.Sub(d.LastSeen) < 15*time.Minute
		if recent {
			a.failing++
			if a.first.IsZero() || d.failSince.Before(a.first) {
				a.first = d.failSince
			}
			if d.failSince.After(a.last) {
				a.last = d.failSince
			}
		}
		if isFixed(d) && (d.Online || recent) {
			a.fActive++
			if recent {
				a.fFailing++
				if a.fFirst.IsZero() || d.failSince.Before(a.fFirst) {
					a.fFirst = d.failSince
				}
				if d.failSince.After(a.fLast) {
					a.fLast = d.failSince
				}
			}
		}
	}
	for k, a := range g {
		if al := s.alerts[k]; al != nil {
			// se recupera cuando vuelve a responder al menos el 30 % de los que cayeron
			// (contando solo los que siguen existiendo: si ya no existe ninguno, se cierra)
			left, back := 0, 0
			for _, key := range al.Keys {
				if d := s.Devs[key]; d != nil {
					left++
					if d.Online {
						back++
					}
				}
			}
			if al.Keys == nil {
				left, back = al.Count, a.online
			}
			if left == 0 || back*100 >= left*30 {
				delete(s.alerts, k)
				if left == 0 {
					s.segEventLocked("info", k, fmt.Sprintf("%s: se cerró la alerta, los equipos que cayeron ya no existen (eran de un mismo aparato)", segLabel(k)))
				} else {
					s.segEventLocked("online", k, fmt.Sprintf("%s se recuperó (estuvo sin respuesta %s)", segLabel(k), fmtDur(now.Sub(al.Since))))
				}
			}
			continue
		}
		switch {
		case a.active >= 3 && a.failing*100 >= a.active*80 && a.last.Sub(a.first) <= 2*time.Minute:
			s.alerts[k] = &segAlert{Since: a.first, Count: a.failing, Keys: s.failedKeysLocked(k, a.first)}
			s.segEventLocked("offline", k, fmt.Sprintf("%s: %d equipos dejaron de responder a la vez. Revisa el switch, el cable o el router de ese segmento", segLabel(k), a.failing))
		case a.fActive >= 2 && a.fFailing == a.fActive && a.fLast.Sub(a.fFirst) <= 2*time.Minute:
			// todos los que deben estar siempre prendidos (impresoras, router…) cayeron juntos
			s.alerts[k] = &segAlert{Since: a.fFirst, Count: a.fFailing, Keys: s.failedKeysLocked(k, a.fFirst)}
			s.segEventLocked("offline", k, fmt.Sprintf("%s: sus %d equipos fijos (impresoras, router…) dejaron de responder a la vez. Revisa el switch, el cable o el router de ese segmento", segLabel(k), a.fFailing))
		}
	}
}

func segLabel(k string) string {
	if k == "169.254" {
		return "Equipos sin IP"
	}
	if n := segName(k); n != "" {
		return n + " (segmento " + k + ")"
	}
	return "Segmento " + k
}

// ---------- internet por segmento ----------
//
// Cada segmento sale a internet por su puerta de enlace (la .254 o la .1 de ese
// segmento). Su internet está "ok" si esa puerta responde y hay internet general
// (revisado por el cable de la Pi); "sin" si la puerta no responde o se cayó el
// internet general; "?" si no se encontró su puerta de enlace.

// internetLocked: ¿hay internet general? (8.8.8.8 / 1.1.1.1 revisados por cable)
func (s *Store) internetLocked() (ok, known bool) {
	for _, t := range s.Tgts {
		if t.Port == 0 && (t.Host == "8.8.8.8" || t.Host == "1.1.1.1") && !t.LastCheck.IsZero() {
			known = true
			ok = ok || t.Online
		}
	}
	return
}

// gatewayOf busca la puerta de enlace de un segmento entre sus equipos.
func gatewayOf(devs []*Device, own map[string]bool) *Device {
	var best *Device
	for _, d := range devs {
		ip := net.ParseIP(d.IP).To4()
		if ip == nil {
			continue
		}
		switch {
		case own[d.IP]:
			return d // la puerta de enlace de la propia Pi
		case ip[3] == 254:
			best = d
		case ip[3] == 1 && best == nil:
			best = d
		}
	}
	return best
}

// ---------- puerta de enlace de cada segmento ----------
//
// Se descubre escuchando: los equipos de un segmento preguntan por ARP "¿quién
// tiene X?" por su puerta de enlace cada vez que salen a internet. La IP por la
// que más equipos DISTINTOS preguntan es la puerta de enlace. Si aún no hay
// suficientes preguntas, se usa la .254 o la .1 si existen.

type gwState struct {
	IP    string
	OK    bool      // última revisión: respondió
	Fails int       // revisiones seguidas sin respuesta
	At    time.Time // última revisión
	Ever  bool      // alguna vez contestó (si nunca, no es prueba de que se cayó)
}

// NoteARPRequest anota que el equipo "from" preguntó por "target" (mismo segmento).
func (s *Store) NoteARPRequest(from, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gwVotes == nil {
		s.gwVotes = map[string]map[string]map[string]bool{}
	}
	k := segOf(target)
	seg := s.gwVotes[k]
	if seg == nil {
		seg = map[string]map[string]bool{}
		s.gwVotes[k] = seg
	}
	v := seg[target]
	if v == nil {
		if len(seg) > 300 {
			return
		}
		v = map[string]bool{}
		seg[target] = v
	}
	if len(v) < 100 {
		v[from] = true
	}
}

// GatewayCandidates devuelve la puerta de enlace a revisar en cada segmento.
func (s *Store) GatewayCandidates() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	own := map[string]bool{}
	for _, ip := range defaultGateways() {
		own[ip] = true
	}
	bySeg := map[string][]*Device{}
	for _, d := range s.Devs {
		bySeg[segOf(d.IP)] = append(bySeg[segOf(d.IP)], d)
	}
	selfIP := ""
	if me := localIface(); me != nil {
		selfIP = me.ip.String()
	}
	// No se usa "misma MAC en varios segmentos" para hallar routers: en la red
	// real hay PCs HP que cambian de IP y aparecen en hasta 22 segmentos.
	// IPs de PCs, teléfonos, impresoras…: contestan, pero no son puerta
	endpoint := map[string]bool{selfIP: true}
	for _, d := range s.Devs {
		if isProbeIP(d.IP) || (endpointKinds[d.Kind] && !own[d.IP]) {
			endpoint[d.IP] = true
		}
	}
	out := map[string]string{}
	for _, c := range SegConfigList() { // fijada a mano (también segmentos sin equipos aún)
		if c.Gateway != "" && !c.Hidden {
			out[c.Seg] = c.Gateway
		}
	}
	for k, devs := range bySeg {
		if _, fixed := out[k]; fixed || segHidden(k) {
			continue
		}
		// 1.º la de la Pi, la .254 o la .1 si existen (la IP "más preguntada" puede
		// ser un servidor o la propia Pi, no el router)
		if gw := gatewayOf(devs, own); gw != nil && !endpoint[gw.IP] {
			out[k] = gw.IP
			continue
		}
		// (No se usa "equipo identificado como red": un access point Ubiquiti se
		// tomó como puerta y al apagarse dio un falso "sin internet".)
		// 2.º la IP más preguntada por al menos 3 equipos distintos
		best, n := "", 0
		for ip, from := range s.gwVotes[k] {
			if endpoint[ip] {
				continue
			}
			if len(from) > n || (len(from) == n && ip > best) {
				best, n = ip, len(from)
			}
		}
		if n >= 3 { // equipos distintos que preguntan por ella
			out[k] = best
			continue
		}
		if k != "169.254" { // nada visto: probar directo .254, .1, .2, .10, .253
			if ip := s.guessGatewayLocked(k, endpoint); ip != "" {
				out[k] = ip
			}
		}
	}
	return out
}

// GatewayHint: IP por la que preguntan (ARP) los equipos de un segmento.
type GatewayHint struct {
	IP string `json:"ip"`
	N  int    `json:"n"` // equipos distintos que preguntan por ella
}

// GatewayHints: las 3 IPs más preguntadas de cada segmento (pistas para fijar
// la puerta a mano), sin contar la IP de la Pi.
func (s *Store) GatewayHints() map[string][]GatewayHint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	selfIP := ""
	if me := localIface(); me != nil {
		selfIP = me.ip.String()
	}
	out := map[string][]GatewayHint{}
	for k, votes := range s.gwVotes {
		var hs []GatewayHint
		for ip, from := range votes {
			if ip != selfIP {
				hs = append(hs, GatewayHint{ip, len(from)})
			}
		}
		sort.Slice(hs, func(i, j int) bool { return hs[i].N > hs[j].N || (hs[i].N == hs[j].N && hs[i].IP < hs[j].IP) })
		if len(hs) > 3 {
			hs = hs[:3]
		}
		if len(hs) > 0 {
			out[k] = hs
		}
	}
	return out
}

// gwGuesses: terminaciones que se prueban como puerta, en orden (la .255 es
// broadcast en /24, no puede ser puerta).
// La .253/.252/.251 NO: son las IPs de prueba de la Pi (opción A); una PC de
// prueba en la .253 del 51 quedó como "puerta" y dio un falso "sin internet".
var gwGuesses = []string{"254", "1", "2", "10"}

// guessGatewayLocked: puerta a probar en un segmento sin pistas. Prueba cada
// terminación de gwGuesses 2 rondas; si nunca contestó pasa a la siguiente, y
// al terminar vuelve a empezar.
func (s *Store) guessGatewayLocked(k string, endpoint map[string]bool) string {
	pre := segPrefix(k)
	// siguiente candidata a partir de la posición i, saltando PCs, teléfonos, etc.
	from := func(i int) string {
		for j := 0; j < len(gwGuesses); j++ {
			ip := pre + "." + gwGuesses[(i+j)%len(gwGuesses)]
			if !endpoint[ip] {
				return ip
			}
		}
		return ""
	}
	g := s.gws[k]
	if g == nil {
		return from(0)
	}
	if !endpoint[g.IP] && (g.Ever || g.Fails < 2) {
		return g.IP
	}
	for i, end := range gwGuesses {
		if g.IP == pre+"."+end {
			return from(i + 1)
		}
	}
	return from(0)
}

// endpointKinds: tipos de equipo que nunca son puerta de enlace.
var endpointKinds = map[string]bool{"pc": true, "windows": true, "mac": true, "linux": true, "celular": true,
	"iphone": true, "impresora": true, "telefono-ip": true, "camara": true, "tv": true, "nas": true,
	"virtual": true, "iot": true, "raspberry": true}

// PruneGateways olvida la puerta de los segmentos que ya no tienen candidata
// (p. ej. se descubrió que era una PC).
func (s *Store) PruneGateways(cands map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.gws {
		if _, ok := cands[k]; !ok {
			delete(s.gws, k)
		}
	}
}

// SetGateway guarda el resultado de revisar la puerta de enlace de un segmento.
func (s *Store) SetGateway(seg, ip string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gws == nil {
		s.gws = map[string]*gwState{}
	}
	g := s.gws[seg]
	if g == nil || g.IP != ip {
		g = &gwState{IP: ip}
		s.gws[seg] = g
	}
	g.OK, g.At = ok, time.Now()
	if ok {
		g.Fails, g.Ever = 0, true
	} else {
		g.Fails++
	}
}

// segNetLocked calcula el internet de cada segmento: "ok", "sin" o "?", y su
// puerta de enlace.
func (s *Store) segNetLocked() (map[string]string, map[string]string) {
	inetOK, inetKnown := s.internetLocked()
	segsSeen := map[string]bool{}
	for _, d := range s.Devs {
		segsSeen[segOf(d.IP)] = true
	}
	// Si la Pi se queda sin internet, solo se sabe de los segmentos que salen por
	// su MISMO router (misma MAC que la puerta de enlace de la Pi). Los de otro
	// router quedan "nd" (no se sabe): la Pi no puede probar su salida.
	macOf := map[string]string{}
	if !inetOK {
		for _, d := range s.Devs {
			macOf[d.IP] = d.MAC
		}
	}
	ownMAC := map[string]bool{}
	for _, ip := range defaultGateways() {
		if m := macOf[ip]; m != "" {
			ownMAC[m] = true
		}
	}
	out, gws := map[string]string{}, map[string]string{}
	for k := range segsSeen {
		g := s.gws[k]
		if g != nil && (g.Ever || segGatewayFixed(k) != "") {
			gws[k] = g.IP // solo la confirmada (contestó alguna vez) o la fijada a mano
		}
		p := s.probeLocked(k)
		if p != nil {
			gws[k] = p.GW // la que de verdad saca a internet
		}
		switch {
		case k == "169.254":
			out[k] = "nd" // equipos sin IP asignada (autoconfigurada): no aplica
		case p != nil && p.OK && p.webDown():
			out[k] = "sin" // llega el ping pero no se navega (DNS o web) 2 min seguidos
		case p != nil && p.OK:
			out[k] = "ok" // probado: sale a internet desde el propio segmento
		case p != nil && p.Fails >= 3:
			out[k] = "sin" // probado: 3 pruebas seguidas (30 s) sin salir a internet
		case p != nil:
			out[k] = s.netLast[k] // 1 o 2 fallas: se conserva lo último conocido
			if out[k] == "" {
				out[k] = "?"
			}
		case !inetKnown:
			out[k] = "?"
		case !inetOK && g != nil && !g.OK && g.Fails >= 3 && g.Ever:
			out[k] = "sin" // además su puerta de enlace no responde
		case !inetOK && (len(ownMAC) == 0 || (g != nil && ownMAC[macOf[g.IP]])):
			out[k] = "sin" // mismo router que la Pi (o no se sabe cuál es el de la Pi)
		case !inetOK:
			out[k] = "nd" // otro router: no se puede saber si tiene internet
		case g == nil:
			out[k] = "?" // aún no se conoce su puerta de enlace
		case g.OK:
			out[k] = "ok"
		case g.Fails >= 3 && g.Ever:
			out[k] = "sin" // su puerta de enlace contestaba y dejó de responder (1.5 min)
		default:
			out[k] = "?"
		}
	}
	return out, gws
}

// evalSegNetLocked actualiza el internet de cada segmento y anota en Eventos
// cuando un segmento con equipos conectados se queda sin internet o lo recupera.
func (s *Store) evalSegNetLocked(now time.Time) {
	nets, gws := s.segNetLocked()
	if s.netSince == nil {
		s.netSince = map[string]time.Time{}
	}
	inetOK, _ := s.internetLocked()
	online := map[string]int{}
	for _, d := range s.Devs {
		if d.Online {
			online[segOf(d.IP)]++
		}
	}
	if s.netLast == nil {
		s.netLast = map[string]string{}
	}
	for k, n := range nets {
		prev := s.netLast[k] // último estado conocido (ok/sin), ignorando "sin verificar"
		if n != "?" && n != "nd" {
			s.netLast[k] = n
		}
		switch {
		case n == "sin" && prev == "ok":
			s.netSince[k] = now
			if inetOK { // si es el internet general, ya hay un solo aviso general
				why := fmt.Sprintf("su puerta de enlace %s no responde", gws[k])
				if p := s.probeLocked(k); p != nil {
					why = p.why()
				}
				s.segEventLocked("offline", k, fmt.Sprintf("%s: %d equipos conectados SIN INTERNET (%s)", segLabel(k), online[k], why))
			}
		case n == "ok" && prev == "sin":
			if t, ok := s.netSince[k]; ok && inetOK {
				s.segEventLocked("online", k, fmt.Sprintf("%s recuperó internet (estuvo sin internet %s)", segLabel(k), fmtDur(now.Sub(t))))
			}
			delete(s.netSince, k)
		}
	}
	// ¿la puerta que probamos es la que usan las PCs? (por la que preguntan por ARP)
	if s.gwWarn == nil {
		s.gwWarn = map[string]string{}
	}
	for k := range s.probes {
		p := s.probes[k]
		pu := s.puertaUsuariosLocked(k)
		if pu == "" || pu == p.GW {
			delete(s.gwWarn, k)
			continue
		}
		if s.gwWarn[k] != pu {
			s.gwWarn[k] = pu
			s.segEventLocked("info", k, fmt.Sprintf("%s: las PCs usan la puerta %s, pero la prueba de internet sale por %s. Revisa /etc/monitoreo/segip.conf", segLabel(k), pu, p.GW))
		}
	}
	s.segNet, s.segGW = nets, gws
}

type SegSummary struct {
	NetSince  time.Time      `json:"netSince,omitempty"`
	Net       string         `json:"net"`              // internet del segmento: ok, sin, ?
	Gateway   string         `json:"gateway"`          // IP de su puerta de enlace
	GwDead    bool           `json:"gwDead,omitempty"` // tiene puerta (fija o detectada) que nunca ha contestado
	Prueba    *ProbeInfo     `json:"prueba,omitempty"` // opción A: prueba desde el propio segmento
	Online    int            `json:"online"`           // equipos conectados (para "N conectados sin internet")
	Down      bool           `json:"down"`             // falla del segmento completo
	DownSince time.Time      `json:"downSince"`
	DownCount int            `json:"downCount"`
	Seg       string         `json:"seg"`
	Name      string         `json:"name,omitempty"` // nombre puesto a mano
	Location  string         `json:"location,omitempty"`
	Total     int            `json:"total"`
	Present   int            `json:"present"` // sin contar desconectados
	Health    map[string]int `json:"health"`
	Unknown   int            `json:"unknown"` // sin ningún nombre
	WithHist  int            `json:"withHist"`
	FailedNow int            `json:"failedNow"` // fallaron en el último chequeo
}

// Segments resume cada segmento sin mandar los equipos (rápido con cientos).
func (s *Store) Segments() []SegSummary {
	m := map[string]*SegSummary{}
	for _, d := range s.DeviceList() {
		k := segOf(d.IP)
		if segHidden(k) {
			continue
		}
		g := m[k]
		if g == nil {
			g = &SegSummary{Seg: k, Name: segName(k), Location: segLocation(k), Health: map[string]int{}}
			m[k] = g
		}
		g.Total++
		g.Health[d.Health]++
		if d.Online {
			g.Online++
		}
		if d.Health == "pendiente" {
			continue // aún en la primera revisión: no cuenta en el total ni en fallas
		}
		if d.Health != "desconectado" {
			g.Present++
			if d.Name == "" && d.Hostname == "" && d.NetBIOS == "" && d.MDNS == "" && !d.Known &&
				(d.Vendor == "" || d.Vendor == "MAC privada (aleatoria)") {
				g.Unknown++
			}
		}
		if n := len(d.History); n > 0 && d.upSinceStart {
			g.WithHist++
			if d.History[n-1].Ms == -1 {
				g.FailedNow++
			}
		}
	}
	out := make([]SegSummary, 0, len(m))
	s.mu.RLock()
	nets, gws := s.segNet, s.segGW
	for _, g := range m {
		if al := s.alerts[g.Seg]; al != nil {
			g.Down, g.DownSince, g.DownCount = true, al.Since, al.Count
		}
		g.Net, g.Gateway, g.NetSince = nets[g.Seg], gws[g.Seg], s.netSince[g.Seg]
		if g.Net == "" {
			g.Net = "?"
		}
		if p := s.probes[g.Seg]; p != nil && p.Ever {
			pr := &ProbeInfo{Ping: p.OK, DNS: p.DNS, Web: p.Web, Puerta: p.GW, PuertaPCs: s.puertaUsuariosLocked(g.Seg)}
			g.Prueba = pr
		}
		if gw := s.gws[g.Seg]; g.Net == "?" && gw != nil && !gw.Ever && gw.Fails >= 3 {
			g.GwDead = true
			if g.Gateway == "" {
				g.Gateway = gw.IP
			}
		}
		out = append(out, *g)
	}
	s.mu.RUnlock()
	return out
}

func (s *Store) UpdateDevice(mac, name, location string, known bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.Devs[mac]; d != nil {
		d.Name, d.Location, d.Known = name, location, known
		s.dirty = true
	}
}

// PruneStale borra los equipos que llevan 30 días sin conectarse y a los que no
// les pusiste nombre (celulares de visitas, equipos que ya no existen).
func (s *Store) PruneStale() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []string
	for k, d := range s.Devs {
		if !d.Online && d.Name == "" && !d.Known && time.Since(d.LastSeen) > 30*24*time.Hour {
			delete(s.Devs, k)
			gone = append(gone, k)
		}
	}
	if len(gone) > 0 {
		s.dropFromDB(gone)
		s.addEventLocked("info", fmt.Sprintf("Se quitaron %d equipos que llevaban 30 días sin conectarse", len(gone)))
	}
}

// SetSubnet recuerda la red vigilada; si cambió, borra los eventos de la anterior.
func (s *Store) SetSubnet(n string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Subnet == n {
		return
	}
	if s.Subnet != "" {
		s.Evts = nil
		s.addEventLocked("info", fmt.Sprintf("Se cambió la red vigilada de %s a %s; se limpiaron los eventos anteriores", s.Subnet, n))
	}
	s.Subnet = n
	s.dirty = true
}

// PruneOutside borra los equipos cuya IP no pertenece a la red vigilada.
func (s *Store) PruneOutside(n *net.IPNet) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gone []string
	for mac, d := range s.Devs {
		if d.Via == "arp" {
			continue // visto en el cable: es de otro segmento del mismo switch
		}
		if ip := net.ParseIP(d.IP); ip != nil && !n.Contains(ip) {
			delete(s.Devs, mac)
			gone = append(gone, mac)
		}
	}
	if len(gone) > 0 {
		s.dropFromDB(gone)
		s.addEventLocked("info", fmt.Sprintf("Se quitaron %d equipos que no son de la red %s", len(gone), n))
	}
	return len(gone)
}

func (s *Store) DeleteDevice(mac string) {
	s.mu.Lock()
	delete(s.Devs, mac)
	s.dropFromDB([]string{mac})
	s.dirty = true
	s.mu.Unlock()
}

func (s *Store) dropFromDB(ids []string) {
	if s.db != nil {
		s.db.DeleteDevices(ids)
	}
}

func (s *Store) Targets() []Target {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Target, 0, len(s.Tgts))
	for _, t := range s.Tgts {
		out = append(out, *t)
	}
	return out
}

func (s *Store) AddTarget(t Target) {
	s.mu.Lock()
	t.ID = newID()
	t.History = nil
	s.Tgts = append(s.Tgts, &t)
	s.dirty = true
	s.mu.Unlock()
}

func (s *Store) DeleteTarget(id string) {
	s.mu.Lock()
	for i, t := range s.Tgts {
		if t.ID == id {
			s.Tgts = append(s.Tgts[:i], s.Tgts[i+1:]...)
			break
		}
	}
	s.dirty = true
	s.mu.Unlock()
}

func (s *Store) TargetResult(id string, ms float64, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.Tgts {
		if t.ID != id {
			continue
		}
		now := time.Now()
		general := t.Port == 0 && (t.Host == "8.8.8.8" || t.Host == "1.1.1.1") // su aviso es el corte general
		if ok != t.Online && !t.LastCheck.IsZero() && !general {
			if ok {
				s.addEventLocked("online", fmt.Sprintf("Objetivo %s responde de nuevo", t.Name))
			} else {
				s.addEventLocked("offline", fmt.Sprintf("Objetivo %s (%s) no responde", t.Name, t.Host))
			}
		}
		t.Online, t.LastCheck = ok, now
		if ok {
			t.LatencyMs = ms
		} else {
			ms = -1
		}
		t.History = pushPoint(t.History, Point{now.Unix(), ms})
		up := 0
		for _, p := range t.History {
			if p.Ms >= 0 {
				up++
			}
		}
		t.Uptime = float64(up) * 100 / float64(len(t.History))
		s.dirty = true
	}
}

// InternetSample recibe la revisión rápida de internet (cada 5 s, 8.8.8.8 y
// 1.1.1.1 por el cable). 2 fallas seguidas = corte (empieza en la primera falla);
// en cuanto alguno responde, termina. Cada corte se guarda en SQLite (1 año).
func (s *Store) InternetSample(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	if !s.inetInit && s.db != nil {
		s.inetInit = true
		// cortes que quedaron abiertos cuando se apagó o reinició la Pi: no se sabe cuánto duraron
		for _, o := range s.db.LoadOutages(now) {
			if o.End == 0 {
				s.db.OutageEnd(o.Start, o.Start, "la Pi se apagó o reinició durante el corte")
			}
		}
	}
	if ok {
		s.inetFails, s.inetFirstFail = 0, 0
	} else {
		s.inetFails++
		if s.inetFails == 1 {
			s.inetFirstFail = now
		}
		if s.inetFails < 2 {
			return
		}
	}
	seg, gw := "", ""
	if me := localIface(); me != nil {
		seg = segOf(me.ip.String())
	}
	if g := defaultGateways(); len(g) > 0 {
		gw = g[0]
	}
	switch {
	case !ok && s.inetDown == 0:
		s.inetDown = s.inetFirstFail
		if s.db != nil {
			s.db.OutageStart(s.inetDown, seg)
		}
		s.addEventLocked("offline", fmt.Sprintf("Se cayó el internet (%s, router %s)", segLabel(seg), gw))
	case ok && s.inetDown != 0:
		if s.db != nil {
			s.db.OutageEnd(s.inetDown, now, "")
		}
		s.addEventLocked("online", fmt.Sprintf("Volvió el internet (estuvo caído %s)", fmtDur(time.Duration(now-s.inetDown)*time.Second)))
		s.inetDown = 0
	}
}

// Outages: registro de cortes de internet de los últimos días.
func (s *Store) Outages(days int) []Outage {
	if s.db == nil {
		return nil
	}
	return s.db.LoadOutages(time.Now().AddDate(0, 0, -days).Unix())
}

func (s *Store) Events() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Event, len(s.Evts))
	for i, e := range s.Evts {
		out[len(s.Evts)-1-i] = e // más recientes primero
	}
	return out
}
