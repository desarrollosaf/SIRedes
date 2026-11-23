// Package web: todo lo que ve el navegador, dentro del programa (go:embed).
//
//	templates/   páginas y pedazos de HTML que arma Go (html/template escapa todo solo)
//	static/      archivos tal cual: estilos, htmx, íconos
//	index.html   panel viejo (JavaScript propio); se va reemplazando pantalla por pantalla
//
// Las pantallas nuevas son Go + htmx: Go arma el HTML y htmx cambia solo el
// pedazo que cambió. Sin Alpine, sin Node, sin nada cargado de internet.
package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"
)

//go:embed templates static index.html
var archivos embed.FS

// huella del contenido de static/: va en la dirección (?v=…) para que el navegador
// baje los archivos nuevos en cuanto cambian y pueda guardarlos en caché mientras tanto.
var huella = func() string {
	h := sha256.New()
	fs.WalkDir(archivos, "static", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := archivos.ReadFile(p)
			h.Write(b)
		}
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:10]
}()

var plantillas = template.Must(template.New("").Funcs(template.FuncMap{
	"huella": func() string { return huella },
}).ParseFS(archivos, "templates/*.html"))

// CSPEstricta: para las pantallas ya pasadas a Go + htmx (sin JavaScript ni estilos en línea).
const CSPEstricta = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

// Render arma la plantilla y la manda. Si falla, no se manda media página.
func Render(w http.ResponseWriter, status int, nombre string, datos any) {
	var b bytes.Buffer
	if err := plantillas.ExecuteTemplate(&b, nombre, datos); err != nil {
		log.Printf("plantilla %s: %v", nombre, err)
		http.Error(w, "error al armar la página", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(b.Bytes())
}

// Static sirve /static/* (estilos, htmx).
func Static() http.Handler {
	sub, _ := fs.Sub(archivos, "static")
	files := http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") == huella { // con huella: no cambia nunca
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// Panel sirve el panel viejo (index.html) mientras se migra.
func Panel(w http.ResponseWriter, r *http.Request) {
	b, _ := archivos.ReadFile("index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// Version y RouterActivo los pone main al arrancar (para el menú y el pie).
var (
	Version      string
	RouterActivo = func() bool { return false }
)

var perfiles = map[string]string{"admin": "Administrador", "operador": "Operador", "consulta": "Consulta"}

// Marco: datos del encabezado, menú y pie de una página.
type Marco struct {
	Titulo, Activa, Usuario, Perfil, PerfilNombre, Version string
	Router                                                 bool
	Puede                                                  bool // Operador o Administrador: puede cambiar cosas
	Admin                                                  bool
}

func NuevoMarco(titulo, activa, usuario, perfil string) Marco {
	return Marco{Titulo: titulo, Activa: activa, Usuario: usuario, Perfil: perfil, PerfilNombre: perfiles[perfil],
		Version: Version, Router: RouterActivo(), Puede: perfil == "admin" || perfil == "operador", Admin: perfil == "admin"}
}

// Hace: "hace 5 min", "hace 2 h", "hace 3 d" o "—".
func Hace(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "hace un momento"
	case d < time.Hour:
		return fmt.Sprintf("hace %d min", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("hace %d h", int(d.Hours()))
	}
	return fmt.Sprintf("hace %d d", int(d.Hours()/24))
}

// NombrePerfil: "Administrador", "Operador" o "Consulta".
func NombrePerfil(p string) string { return perfiles[p] }

// EsHTMX: la petición la hizo htmx (quiere solo un pedazo, no la página entera).
func EsHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }
