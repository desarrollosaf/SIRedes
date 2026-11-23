package cuentas

// login.go — pantalla de entrada con Go + htmx.
//
//	GET  /login   página completa (si ya hay sesión, manda al panel)
//	POST /login   con htmx: si falla, responde solo el texto del error (cambia #error);
//	              si entra, HX-Redirect al panel. Sin htmx: formulario normal.
//
// Sin JavaScript propio ni estilos en línea: esta página va con CSP estricta.

import (
	"fmt"
	"net/http"
	"strings"

	"monitoreo/web"
)

type datosLogin struct {
	Primera bool
	Usuario string
	Error   string
}

func (a *Auth) paginaLogin(w http.ResponseWriter, r *http.Request) {
	if u, _ := a.Who(r); u != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Security-Policy", web.CSPEstricta)
	web.Render(w, http.StatusOK, "login", datosLogin{Primera: a.NeedSetup()})
}

func (a *Auth) entrarLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	usuario := strings.ToLower(strings.TrimSpace(r.PostForm.Get("usuario")))
	clave, clave2 := r.PostForm.Get("clave"), r.PostForm.Get("clave2")

	falla := func(msg string) {
		w.Header().Set("Content-Security-Policy", web.CSPEstricta)
		if web.EsHTMX(r) {
			// htmx solo cambia #error; 200 para que lo pinte (con 4xx no lo haría)
			web.Render(w, http.StatusOK, "login-error", msg)
			return
		}
		web.Render(w, http.StatusUnauthorized, "login", datosLogin{Primera: a.NeedSetup(), Usuario: usuario, Error: msg})
	}

	if a.NeedSetup() { // primera vez: esta cuenta será el administrador
		if clave != clave2 {
			falla("Las contraseñas no coinciden")
			return
		}
		if err := a.SetUser(usuario, "admin", clave, true); err != nil {
			falla(err.Error())
			return
		}
		a.ev.AddEvent("info", fmt.Sprintf("Se creó el primer administrador: %s", usuario))
		a.secLog(r, "cuenta", usuario, "primer administrador")
	}
	tok, err := a.Login(usuario, clave, clientIP(r))
	if err != nil {
		tipo := "fallo"
		if err == errBloqueo {
			tipo = "bloqueo"
		}
		a.secLog(r, tipo, usuario, "")
		falla(err.Error())
		return
	}
	a.secLog(r, "entrada", usuario, "")
	setSessionCookie(w, r, tok, int(sessionTTL.Seconds()))
	if web.EsHTMX(r) {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
