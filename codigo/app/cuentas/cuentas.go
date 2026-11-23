// auth.go — cuentas, inicio de sesión y permisos por perfil.
//
// Perfiles:
//
//	admin     todo, incluidas las cuentas
//	operador  nombres, ubicaciones, segmentos, servicios y escaneo (sin cuentas)
//	consulta  solo ver
//
// Las claves se guardan con PBKDF2-SHA256 (sal por cuenta). La sesión es una
// cookie HttpOnly con un token aleatorio; en la base solo queda su SHA-256.
// Si no hay cuentas, la pantalla de entrada pide crear el primer administrador.
// La API v1 (/api/v1/) sigue con su propio token y no pasa por aquí.
//
// Archivos: cuentas.go (cuentas, sesiones, bitácora y rutas JSON) y login.go
// (pantalla de entrada con Go + htmx).
package cuentas

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"monitoreo/middleware"
)

// Almacen: la base SQLite de la app (escrituras en lote y lecturas directas).
type Almacen interface {
	Do(func(*sql.Tx) error)
	SQL() *sql.DB
}

// Eventos: donde se anotan los eventos visibles en el panel.
type Eventos interface{ AddEvent(kind, msg string) }

func escribirJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

const (
	cookieName   = "mr_sesion"
	sessionTTL   = 7 * 24 * time.Hour
	pbkdfIter    = 120000
	loginMaxFail = 5
	loginLockout = 5 * time.Minute
)

var roleRank = map[string]int{"consulta": 1, "operador": 2, "admin": 3}

type User struct {
	Name    string    `json:"usuario"`
	Role    string    `json:"perfil"`
	Salt    string    `json:"-"`
	Hash    string    `json:"-"`
	Created time.Time `json:"creado"`
	Last    time.Time `json:"ultimo,omitempty"` // último inicio de sesión
}

type session struct {
	user string
	exp  time.Time
}

type Auth struct {
	mu    sync.Mutex
	db    Almacen
	users map[string]*User
	sess  map[string]*session // sha256(token) → sesión
	fails map[string][]time.Time
	ev    Eventos
}

const authSchema = `
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(h TEXT PRIMARY KEY, user TEXT, exp INTEGER);
CREATE TABLE IF NOT EXISTS sec_log(t INTEGER, tipo TEXT, usuario TEXT, ip TEXT, agente TEXT, detalle TEXT);
CREATE INDEX IF NOT EXISTS sec_log_t ON sec_log(t);`

// Nuevo carga cuentas y sesiones. db puede ser nil (sin base: todo en memoria).
func Nuevo(db Almacen, ev Eventos) *Auth {
	a := &Auth{db: db, users: map[string]*User{}, sess: map[string]*session{}, fails: map[string][]time.Time{}, ev: ev}
	if db == nil {
		return a
	}
	db.SQL().Exec(authSchema)
	if rows, err := db.SQL().Query(`SELECT data FROM users`); err == nil {
		for rows.Next() {
			var s string
			var u struct {
				User
				S string `json:"s"`
				H string `json:"h"`
			}
			if rows.Scan(&s) == nil && json.Unmarshal([]byte(s), &u) == nil && u.Name != "" {
				u.User.Salt, u.User.Hash = u.S, u.H
				cp := u.User
				a.users[cp.Name] = &cp
			}
		}
		rows.Close()
	}
	now := time.Now().Unix()
	if rows, err := db.SQL().Query(`SELECT h, user, exp FROM sessions WHERE exp > ?`, now); err == nil {
		for rows.Next() {
			var h, u string
			var exp int64
			if rows.Scan(&h, &u, &exp) == nil && a.users[u] != nil {
				a.sess[h] = &session{user: u, exp: time.Unix(exp, 0)}
			}
		}
		rows.Close()
	}
	db.SQL().Exec(`DELETE FROM sessions WHERE exp <= ?`, now)
	db.SQL().Exec(`DELETE FROM sec_log WHERE t < ?`, now-365*86400) // bitácora: 1 año
	return a
}

// ---------- bitácora de seguridad ----------

// SecEntry: un renglón de la bitácora (entradas, fallos, bloqueos, cuentas…).
type SecEntry struct {
	T       time.Time `json:"t"`
	Tipo    string    `json:"tipo"`
	Usuario string    `json:"usuario"`
	IP      string    `json:"ip"`
	Agente  string    `json:"agente,omitempty"`
	Detalle string    `json:"detalle,omitempty"`
}

// agente: navegador y sistema en pocas palabras (el User-Agent completo es enorme)
func agente(r *http.Request) string {
	ua := r.UserAgent()
	nav, so := "", ""
	for _, n := range [][2]string{{"Edg/", "Edge"}, {"OPR/", "Opera"}, {"Firefox/", "Firefox"}, {"Chrome/", "Chrome"}, {"Safari/", "Safari"}} {
		if strings.Contains(ua, n[0]) {
			nav = n[1]
			break
		}
	}
	for _, o := range []string{"Windows", "Android", "iPhone", "iPad", "Mac OS", "Linux"} {
		if strings.Contains(ua, o) {
			so = o
			break
		}
	}
	if nav == "" && so == "" {
		if len(ua) > 60 {
			ua = ua[:60]
		}
		return ua
	}
	return strings.Trim(nav+" · "+so, " ·")
}

func (a *Auth) secLog(r *http.Request, tipo, usuario, detalle string) {
	if a.db == nil {
		return
	}
	ip, ag, t := middleware.IPReal(r), agente(r), time.Now().Unix()
	a.db.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO sec_log(t,tipo,usuario,ip,agente,detalle) VALUES(?,?,?,?,?,?)`, t, tipo, usuario, ip, ag, detalle)
		return err
	})
}

// SecLog: lo más reciente primero (máx. 500).
func (a *Auth) SecLog(dias int) []SecEntry {
	out := []SecEntry{}
	if a.db == nil {
		return out
	}
	rows, err := a.db.SQL().Query(`SELECT t,tipo,usuario,ip,agente,detalle FROM sec_log WHERE t >= ? ORDER BY t DESC LIMIT 500`,
		time.Now().Add(-time.Duration(dias)*24*time.Hour).Unix())
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var e SecEntry
		var t int64
		var ag, det sql.NullString
		if rows.Scan(&t, &e.Tipo, &e.Usuario, &e.IP, &ag, &det) == nil {
			e.T, e.Agente, e.Detalle = time.Unix(t, 0), ag.String, det.String
			out = append(out, e)
		}
	}
	return out
}

var errBloqueo = fmt.Errorf("demasiados intentos; espera unos minutos")

func hashPass(pass, salt string) string {
	k, _ := pbkdf2.Key(sha256.New, pass, []byte(salt), pbkdfIter, 32)
	return hex.EncodeToString(k)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func tokenHash(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func (a *Auth) saveUser(u *User) {
	if a.db == nil {
		return
	}
	b, _ := json.Marshal(struct {
		User
		S string `json:"s"`
		H string `json:"h"`
	}{*u, u.Salt, u.Hash})
	a.db.Do(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO users(name,data) VALUES(?,?)`, u.Name, string(b))
		return err
	})
}

func validName(n string) bool {
	if len(n) < 2 || len(n) > 32 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validPass(p string) error {
	if len([]rune(p)) < 8 {
		return fmt.Errorf("la contraseña debe tener al menos 8 caracteres")
	}
	return nil
}

// NeedSetup: no hay cuentas todavía.
func (a *Auth) NeedSetup() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.users) == 0
}

// SetUser crea o cambia una cuenta. pass vacío = no cambia la clave.
func (a *Auth) SetUser(name, role, pass string, create bool) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if !validName(name) {
		return fmt.Errorf("usuario inválido: 2 a 32 letras minúsculas, números, punto, guion")
	}
	if roleRank[role] == 0 {
		return fmt.Errorf("perfil inválido")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[name]
	switch {
	case create && u != nil:
		return fmt.Errorf("ya existe la cuenta %s", name)
	case !create && u == nil:
		return fmt.Errorf("no existe la cuenta %s", name)
	case u == nil && pass == "":
		return fmt.Errorf("falta la contraseña")
	}
	if pass != "" {
		if err := validPass(pass); err != nil {
			return err
		}
	}
	if u != nil && u.Role == "admin" && role != "admin" && a.adminsLocked() == 1 {
		return fmt.Errorf("debe quedar al menos un administrador")
	}
	if u == nil {
		u = &User{Name: name, Created: time.Now()}
		a.users[name] = u
	}
	u.Role = role
	if pass != "" {
		u.Salt = randHex(16)
		u.Hash = hashPass(pass, u.Salt)
		a.dropSessionsLocked(name, "") // con clave nueva se cierra en todos lados
	}
	a.saveUser(u)
	return nil
}

func (a *Auth) adminsLocked() int {
	n := 0
	for _, u := range a.users {
		if u.Role == "admin" {
			n++
		}
	}
	return n
}

func (a *Auth) DeleteUser(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := a.users[name]
	if u == nil {
		return fmt.Errorf("no existe la cuenta")
	}
	if u.Role == "admin" && a.adminsLocked() == 1 {
		return fmt.Errorf("debe quedar al menos un administrador")
	}
	delete(a.users, name)
	a.dropSessionsLocked(name, "")
	if a.db != nil {
		a.db.Do(func(tx *sql.Tx) error { _, err := tx.Exec(`DELETE FROM users WHERE name=?`, name); return err })
	}
	return nil
}

func (a *Auth) Users() []User {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]User, 0, len(a.users))
	for _, u := range a.users {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// dropSessionsLocked cierra las sesiones de un usuario menos keep (hash).
func (a *Auth) dropSessionsLocked(user, keep string) {
	for h, s := range a.sess {
		if s.user == user && h != keep {
			delete(a.sess, h)
			if a.db != nil {
				hh := h
				a.db.Do(func(tx *sql.Tx) error { _, err := tx.Exec(`DELETE FROM sessions WHERE h=?`, hh); return err })
			}
		}
	}
}

func clientIP(r *http.Request) string { return middleware.IPReal(r) }

// Login revisa usuario y clave; devuelve el token de sesión.
func (a *Auth) Login(name, pass, ip string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	recent := a.fails[ip][:0]
	for _, t := range a.fails[ip] {
		if now.Sub(t) < loginLockout {
			recent = append(recent, t)
		}
	}
	a.fails[ip] = recent
	if len(recent) >= loginMaxFail {
		return "", errBloqueo
	}
	u := a.users[name]
	salt := "x"
	if u != nil {
		salt = u.Salt
	}
	got := hashPass(pass, salt) // se calcula siempre: mismo tiempo exista o no la cuenta
	if u == nil || subtle.ConstantTimeCompare([]byte(got), []byte(u.Hash)) != 1 {
		a.fails[ip] = append(a.fails[ip], now)
		return "", fmt.Errorf("usuario o contraseña incorrectos")
	}
	delete(a.fails, ip)
	tok := randHex(32)
	h := tokenHash(tok)
	exp := now.Add(sessionTTL)
	a.sess[h] = &session{user: name, exp: exp}
	u.Last = now
	a.saveUser(u)
	if a.db != nil {
		a.db.Do(func(tx *sql.Tx) error {
			_, err := tx.Exec(`INSERT OR REPLACE INTO sessions(h,user,exp) VALUES(?,?,?)`, h, name, exp.Unix())
			return err
		})
	}
	return tok, nil
}

// Who devuelve la cuenta de la petición (nil = sin sesión válida).
func (a *Auth) Who(r *http.Request) (*User, string) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil, ""
	}
	h := tokenHash(c.Value)
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sess[h]
	if s == nil || time.Now().After(s.exp) {
		return nil, ""
	}
	u := a.users[s.user]
	if u == nil {
		return nil, ""
	}
	cp := *u
	return &cp, h
}

func (a *Auth) Logout(h string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sess, h)
	if a.db != nil {
		a.db.Do(func(tx *sql.Tx) error { _, err := tx.Exec(`DELETE FROM sessions WHERE h=?`, h); return err })
	}
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil, MaxAge: maxAge})
}

// ---------- protección de rutas (middleware de chi) ----------

type ctxUser struct{}

// Sesion: la ruta pide una sesión válida (si no, 401). Deja la cuenta en el contexto.
func (a *Auth) Sesion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := a.Who(r)
		switch {
		case u != nil:
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUser{}, u)))
		case strings.HasPrefix(r.URL.Path, "/api/"):
			http.Error(w, "inicia sesión", http.StatusUnauthorized)
		case r.Header.Get("HX-Request") == "true": // la sesión venció con la página abierta
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
	})
}

// Cuenta de la petición (puesta por Sesion).
func Cuenta(r *http.Request) *User {
	u, _ := r.Context().Value(ctxUser{}).(*User)
	return u
}

// PuedeCambiar: consultar (GET) basta con Consulta; cualquier cambio pide Operador.
func PuedeCambiar(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && roleRank[Cuenta(r).Role] < roleRank["operador"] {
			http.Error(w, "tu perfil no permite este cambio", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SoloAdmin: la ruta es solo para administradores (cuentas y bitácora).
func SoloAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Cuenta(r).Role != "admin" {
			http.Error(w, "solo un administrador puede ver esto", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func leerJSON(r *http.Request, v any) bool {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(v) == nil
}

// RutasPublicas: /api/auth/* (quién soy, salir, cambiar mi clave) y /login.
func (a *Auth) RutasPublicas(mux chi.Router) {
	mux.Get("/login", a.paginaLogin)
	mux.Post("/login", a.entrarLogin)
	mux.Post("/salir", a.salir)
	mux.Get("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusMovedPermanently)
	})
	body := leerJSON
	mux.HandleFunc("/api/auth/sesion", func(w http.ResponseWriter, r *http.Request) {
		u, _ := a.Who(r)
		if u == nil {
			escribirJSON(w, map[string]any{"sesion": false, "primera": a.NeedSetup()})
			return
		}
		escribirJSON(w, map[string]any{"sesion": true, "usuario": u.Name, "perfil": u.Role})
	})
	mux.HandleFunc("/api/auth/salir", func(w http.ResponseWriter, r *http.Request) {
		if u, h := a.Who(r); h != "" {
			a.Logout(h)
			a.secLog(r, "salida", u.Name, "")
		}
		setSessionCookie(w, r, "", -1)
		escribirJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/auth/clave", func(w http.ResponseWriter, r *http.Request) {
		// cambiar la propia contraseña (cualquier perfil): {actual, nueva}
		u, h := a.Who(r)
		if u == nil || r.Method != http.MethodPost {
			http.Error(w, "inicia sesión", 401)
			return
		}
		var q struct{ Actual, Nueva string }
		if !body(r, &q) {
			http.Error(w, "datos inválidos", 400)
			return
		}
		if _, err := a.Login(u.Name, q.Actual, clientIP(r)); err != nil {
			a.secLog(r, "fallo", u.Name, "contraseña actual incorrecta al cambiarla")
			http.Error(w, "la contraseña actual no es correcta", 400)
			return
		}
		if err := a.SetUser(u.Name, u.Role, q.Nueva, false); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		// SetUser cerró todas sus sesiones; se abre una nueva para seguir aquí
		_ = h
		a.secLog(r, "clave", u.Name, "cambió su contraseña")
		tok, _ := a.Login(u.Name, q.Nueva, clientIP(r))
		setSessionCookie(w, r, tok, int(sessionTTL.Seconds()))
		escribirJSON(w, map[string]bool{"ok": true})
	})
}

// RutasAdmin (solo admin): /api/usuarios y /api/seguridad.
func (a *Auth) RutasAdmin(mux chi.Router) {
	body := leerJSON
	mux.HandleFunc("/api/seguridad", func(w http.ResponseWriter, r *http.Request) {
		// bitácora de seguridad (solo admin, lo revisa el middleware): ?dias=30
		d, _ := strconv.Atoi(r.URL.Query().Get("dias"))
		if d <= 0 || d > 365 {
			d = 30
		}
		escribirJSON(w, a.SecLog(d))
	})
	mux.HandleFunc("/api/usuarios", func(w http.ResponseWriter, r *http.Request) {
		// GET lista | POST {usuario, perfil, clave, nuevo} | DELETE ?usuario=
		me := Cuenta(r)
		switch r.Method {
		case http.MethodGet:
			escribirJSON(w, a.Users())
		case http.MethodPost:
			var q struct {
				Usuario, Perfil, Clave string
				Nuevo                  bool
			}
			if !body(r, &q) {
				http.Error(w, "datos inválidos", 400)
				return
			}
			if err := a.SetUser(q.Usuario, q.Perfil, q.Clave, q.Nuevo); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			verb := "cambió"
			if q.Nuevo {
				verb = "creó"
			}
			a.ev.AddEvent("info", fmt.Sprintf("%s %s la cuenta %s (%s)", me.Name, verb, strings.ToLower(q.Usuario), q.Perfil))
			det := fmt.Sprintf("%s la cuenta %s (%s)", verb, strings.ToLower(q.Usuario), q.Perfil)
			if q.Clave != "" && !q.Nuevo {
				det += " y su contraseña"
			}
			a.secLog(r, "cuenta", me.Name, det)
			escribirJSON(w, map[string]bool{"ok": true})
		case http.MethodDelete:
			n := r.URL.Query().Get("usuario")
			if n == me.Name {
				http.Error(w, "no puedes borrar tu propia cuenta", 400)
				return
			}
			if err := a.DeleteUser(n); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			a.ev.AddEvent("info", fmt.Sprintf("%s borró la cuenta %s", me.Name, n))
			a.secLog(r, "cuenta", me.Name, "borró la cuenta "+n)
			escribirJSON(w, map[string]bool{"ok": true})
		default:
			http.Error(w, "método no permitido", 405)
		}
	})
}
