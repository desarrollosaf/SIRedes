package main

// Guardado en SQLite (un solo archivo, sin servidor aparte). Se escribe solo lo
// nuevo, por lotes, para cuidar la memoria SD:
//
//   devices        estado de cada equipo (nombre, tipo, salud…), cada 10 min
//   targets        Internet y servicios
//   events         todos los eventos (1 año)
//   device_samples resumen por equipo cada 30 min (90 días): latencia y pérdidas
//   seg_samples    resumen por segmento cada 5 min (1 año): para pronósticos y reportes
//   meta           versión, red vigilada
//
// Grafana (u otra herramienta) puede leer este archivo directamente.

import (
	"database/sql"
	"encoding/json"
	"log"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	keepDeviceSamples = 90 * 24 * time.Hour
	keepSegSamples    = 365 * 24 * time.Hour
	keepEvents        = 365 * 24 * time.Hour
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, seg TEXT, data TEXT NOT NULL, updated INTEGER);
CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY, t INTEGER NOT NULL, kind TEXT, seg TEXT, device TEXT, message TEXT);
CREATE INDEX IF NOT EXISTS events_t ON events(t);
CREATE INDEX IF NOT EXISTS events_seg ON events(seg, t);
CREATE TABLE IF NOT EXISTS device_samples(
  device TEXT NOT NULL, t INTEGER NOT NULL, sum_ms REAL, max_ms REAL, ok INTEGER, lost INTEGER,
  PRIMARY KEY(device, t)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS device_samples_t ON device_samples(t);
CREATE TABLE IF NOT EXISTS seg_samples(
  seg TEXT NOT NULL, t INTEGER NOT NULL, total INTEGER, present INTEGER, online INTEGER,
  normal INTEGER, inestable INTEGER, problema INTEGER, caido INTEGER, desconectado INTEGER,
  avg_ms REAL, loss REAL, down INTEGER,
  PRIMARY KEY(seg, t)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS inet_outages(
  start INTEGER PRIMARY KEY, end INTEGER NOT NULL DEFAULT 0, seg TEXT, note TEXT);
`

type DB struct {
	sql *sql.DB
	q   chan func(*sql.Tx) error // escrituras pendientes (se juntan en lotes)
}

// SQL: lecturas directas (los paquetes de app/ lo usan por la interfaz Almacen).
func (d *DB) SQL() *sql.DB { return d.sql }

func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: un solo escritor
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// columnas agregadas después (si ya existen, SQLite da error y se ignora)
	db.Exec(`ALTER TABLE seg_samples ADD COLUMN net TEXT`)
	db.Exec(`ALTER TABLE seg_samples ADD COLUMN sin_internet INTEGER`)
	d := &DB{sql: db, q: make(chan func(*sql.Tx) error, 20000)}
	go d.writer()
	go d.cleaner()
	return d, nil
}

// writer junta las escrituras y las aplica en una sola transacción cada 2 s.
func (d *DB) writer() {
	tick := time.NewTicker(2 * time.Second)
	var batch []func(*sql.Tx) error
	flush := func() {
		if len(batch) == 0 {
			return
		}
		tx, err := d.sql.Begin()
		if err != nil {
			log.Printf("db: %v", err)
			batch = batch[:0]
			return
		}
		for _, f := range batch {
			if err := f(tx); err != nil {
				log.Printf("db: %v", err)
			}
		}
		if err := tx.Commit(); err != nil {
			log.Printf("db: %v", err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case f, ok := <-d.q:
			if !ok {
				flush()
				return
			}
			batch = append(batch, f)
			if len(batch) >= 2000 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// Do encola una escritura (no bloquea el monitoreo).
func (d *DB) Do(f func(*sql.Tx) error) {
	select {
	case d.q <- f:
	default:
		log.Printf("db: cola llena, se descarta una escritura")
	}
}

// Flush espera a que se escriba todo lo pendiente (al detener el servicio).
func (d *DB) Flush() {
	done := make(chan struct{})
	d.Do(func(*sql.Tx) error { close(done); return nil })
	select {
	case <-done:
	case <-time.After(15 * time.Second):
	}
	// el writer hace commit justo después de ejecutar la función; esperar un poco
	time.Sleep(300 * time.Millisecond)
}

// cleaner borra una vez al día lo que ya pasó su tiempo de guardado.
func (d *DB) cleaner() {
	for {
		now := time.Now()
		d.Do(func(tx *sql.Tx) error {
			tx.Exec(`DELETE FROM device_samples WHERE t < ?`, now.Add(-keepDeviceSamples).Unix())
			tx.Exec(`DELETE FROM seg_samples WHERE t < ?`, now.Add(-keepSegSamples).Unix())
			tx.Exec(`DELETE FROM inet_outages WHERE start < ?`, now.Add(-365*24*time.Hour).Unix())
			_, err := tx.Exec(`DELETE FROM events WHERE t < ?`, now.Add(-keepEvents).Unix())
			return err
		})
		time.Sleep(24 * time.Hour)
	}
}

// ---------- escrituras ----------

func (d *DB) AddEvent(e Event, seg, device string) {
	d.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO events(t,kind,seg,device,message) VALUES(?,?,?,?,?)`,
			e.Time.Unix(), e.Kind, seg, device, e.Message)
		return err
	})
}

func (d *DB) PutBucket(device string, b Bucket) {
	d.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO device_samples(device,t,sum_ms,max_ms,ok,lost) VALUES(?,?,?,?,?,?)`,
			device, int64(b[0]), b[1], b[2], int(b[3]), int(b[4]))
		return err
	})
}

func (d *DB) PutSegSample(t int64, g SegSummary, avg, loss float64) {
	d.Do(func(tx *sql.Tx) error {
		// net: internet del segmento (ok/sin/?); sin_internet: equipos conectados sin internet
		sinNet := 0
		if g.Net == "sin" {
			sinNet = g.Online
		}
		_, err := tx.Exec(`INSERT OR REPLACE INTO seg_samples(seg,t,total,present,online,normal,inestable,problema,caido,desconectado,avg_ms,loss,down,net,sin_internet)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			g.Seg, t, g.Total, g.Present, g.Online, g.Health["normal"], g.Health["inestable"],
			g.Health["problema"], 0, g.Health["desconectado"], avg, loss, btoi(g.Down), g.Net, sinNet)
		return err
	})
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SaveState guarda el estado de equipos, objetivos y datos generales.
func (d *DB) SaveState(devs []Device, tgts []Target, meta map[string]string) {
	now := time.Now().Unix()
	d.Do(func(tx *sql.Tx) error {
		st, err := tx.Prepare(`INSERT OR REPLACE INTO devices(id,seg,data,updated) VALUES(?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, dv := range devs {
			b, _ := json.Marshal(dv)
			st.Exec(dv.ID, segOf(dv.IP), string(b), now)
		}
		tx.Exec(`DELETE FROM targets`)
		for _, t := range tgts {
			b, _ := json.Marshal(t)
			tx.Exec(`INSERT INTO targets(id,data) VALUES(?,?)`, t.ID, string(b))
		}
		for k, v := range meta {
			tx.Exec(`INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)`, k, v)
		}
		return nil
	})
}

func (d *DB) DeleteDevices(ids []string) {
	if len(ids) == 0 {
		return
	}
	d.Do(func(tx *sql.Tx) error {
		for _, id := range ids {
			tx.Exec(`DELETE FROM devices WHERE id=?`, id)
			tx.Exec(`DELETE FROM device_samples WHERE device=?`, id)
		}
		return nil
	})
}

// ---------- lecturas ----------

func (d *DB) Meta(k string) string {
	var v string
	d.sql.QueryRow(`SELECT v FROM meta WHERE k=?`, k).Scan(&v)
	return v
}

func (d *DB) LoadDevices() (map[string]*Device, error) {
	rows, err := d.sql.Query(`SELECT id, data FROM devices`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*Device{}
	for rows.Next() {
		var id, data string
		if rows.Scan(&id, &data) != nil {
			continue
		}
		var dv Device
		if json.Unmarshal([]byte(data), &dv) == nil {
			dv.ID = id
			out[id] = &dv
		}
	}
	return out, rows.Err()
}

func (d *DB) LoadTargets() []*Target {
	rows, err := d.sql.Query(`SELECT data FROM targets`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*Target
	for rows.Next() {
		var data string
		var t Target
		if rows.Scan(&data) == nil && json.Unmarshal([]byte(data), &t) == nil {
			out = append(out, &t)
		}
	}
	return out
}

// LoadBuckets devuelve los resúmenes de 30 min de los últimos 7 días por equipo.
func (d *DB) LoadBuckets(since int64) map[string][]Bucket {
	out := map[string][]Bucket{}
	rows, err := d.sql.Query(`SELECT device,t,sum_ms,max_ms,ok,lost FROM device_samples WHERE t >= ? ORDER BY device, t`, since)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var t int64
		var sum, max float64
		var ok, lost int
		if rows.Scan(&id, &t, &sum, &max, &ok, &lost) == nil {
			out[id] = append(out[id], Bucket{float64(t), sum, max, float64(ok), float64(lost)})
		}
	}
	return out
}

// ---------- cortes de internet ----------

type Outage struct {
	Start int64  `json:"start"`
	End   int64  `json:"end"` // 0 = sigue sin internet
	Seg   string `json:"seg"`
	Note  string `json:"note,omitempty"`
}

func (d *DB) OutageStart(start int64, seg string) {
	d.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO inet_outages(start,end,seg) VALUES(?,0,?)`, start, seg)
		return err
	})
}

func (d *DB) OutageEnd(start, end int64, note string) {
	d.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE inet_outages SET end=?, note=? WHERE start=?`, end, note, start)
		return err
	})
}

// LoadOutages: cortes desde "since" (más recientes primero).
func (d *DB) LoadOutages(since int64) []Outage {
	rows, err := d.sql.Query(`SELECT start,end,COALESCE(seg,''),COALESCE(note,'') FROM inet_outages WHERE start >= ? OR end = 0 ORDER BY start DESC LIMIT 5000`, since)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Outage
	for rows.Next() {
		var o Outage
		if rows.Scan(&o.Start, &o.End, &o.Seg, &o.Note) == nil {
			out = append(out, o)
		}
	}
	return out
}

// QueryEvents: eventos filtrados (más recientes primero). seg "" = todos,
// "-" = generales (sin segmento: internet, la Pi); kinds vacío = todos los tipos;
// q busca en el texto; since = desde (unix).
func (d *DB) QueryEvents(seg string, kinds []string, q string, since int64, limit int) []Event {
	where, args := []string{"t >= ?"}, []any{since}
	switch seg {
	case "":
	case "-":
		where = append(where, "COALESCE(seg,'') = ''")
	default:
		where = append(where, "seg = ?")
		args = append(args, seg)
	}
	if len(kinds) > 0 {
		where = append(where, "kind IN (?"+strings.Repeat(",?", len(kinds)-1)+")")
		for _, k := range kinds {
			args = append(args, k)
		}
	}
	if q != "" {
		where = append(where, "message LIKE ?")
		args = append(args, "%"+q+"%")
	}
	args = append(args, limit)
	rows, err := d.sql.Query(`SELECT t,kind,COALESCE(seg,''),message FROM events WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var t int64
		var e Event
		if rows.Scan(&t, &e.Kind, &e.Seg, &e.Message) == nil {
			e.Time = time.Unix(t, 0)
			out = append(out, e)
		}
	}
	return out
}

// LoadEvents devuelve los últimos n eventos (más viejos primero).
func (d *DB) LoadEvents(n int) []Event {
	rows, err := d.sql.Query(`SELECT t,kind,seg,message FROM (SELECT t,kind,COALESCE(seg,'') AS seg,message,id FROM events ORDER BY id DESC LIMIT ?) ORDER BY id`, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var t int64
		var e Event
		if rows.Scan(&t, &e.Kind, &e.Seg, &e.Message) == nil {
			e.Time = time.Unix(t, 0)
			out = append(out, e)
		}
	}
	return out
}
