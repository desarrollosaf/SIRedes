package cuentas

// ui.go — pantallas de cuentas con Go + htmx:
//
//	POST /salir                          cerrar sesión (formulario del menú de cuenta)
//	GET|POST /cuenta/clave               cambiar mi contraseña (ventana; cualquier perfil)
//	Configuración → Usuarios (solo admin):
//	GET  /configuracion/usuarios/nueva   ventana nueva cuenta
//	GET  /configuracion/usuarios/editar?u=
//	POST /configuracion/usuarios         guardar (nueva o cambio)
//	DELETE /configuracion/usuarios?u=    borrar

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"monitoreo/web"
)

// FilaUsuario y FilaBitacora: lo que muestra la tabla, ya en palabras.
type FilaUsuario struct {
	Usuario, Perfil, PerfilNombre, Ultimo string
	Yo                                    bool
}

type FilaBitacora struct {
	Cuando, Usuario, Que, Clase, IP, Agente string
}

// DatosUsuarios: Configuración → Usuarios.
type DatosUsuarios struct {
	Usuarios []FilaUsuario
	Bitacora []FilaBitacora
	Aviso    string
}

var queBitacora = map[string][2]string{
	"entrada": {"Entró", ""}, "salida": {"Salió", ""}, "fallo": {"Falló la entrada", "warn"},
	"bloqueo": {"Bloqueado por intentos", "bad"}, "clave": {"Cambió su contraseña", ""}, "cuenta": {"Cuentas", ""},
}

// Usuarios arma los datos de la pestaña (yo = quien la ve).
func (a *Auth) DatosUsuarios(yo, aviso string) DatosUsuarios {
	d := DatosUsuarios{Aviso: aviso}
	for _, u := range a.Users() {
		d.Usuarios = append(d.Usuarios, FilaUsuario{Usuario: u.Name, Perfil: u.Role, PerfilNombre: web.NombrePerfil(u.Role),
			Ultimo: web.Hace(u.Last), Yo: u.Name == yo})
	}
	for _, e := range a.SecLog(30) {
		q := queBitacora[e.Tipo]
		if q[0] == "" {
			q[0] = e.Tipo
		}
		if e.Detalle != "" {
			q[0] = e.Detalle
		}
		d.Bitacora = append(d.Bitacora, FilaBitacora{Cuando: e.T.Format("02/01/06 15:04"), Usuario: e.Usuario,
			Que: q[0], Clase: q[1], IP: e.IP, Agente: e.Agente})
	}
	return d
}

// Registrar anota en la bitácora de seguridad (para otros paquetes).
func (a *Auth) Registrar(r *http.Request, tipo, usuario, detalle string) {
	a.secLog(r, tipo, usuario, detalle)
}

// salir: formulario del menú de cuenta.
func (a *Auth) salir(w http.ResponseWriter, r *http.Request) {
	if u, h := a.Who(r); h != "" {
		a.Logout(h)
		a.secLog(r, "salida", u.Name, "")
	}
	setSessionCookie(w, r, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// RutasCuenta (con sesión, cualquier perfil): cambiar mi contraseña.
func (a *Auth) RutasCuenta(r chi.Router) {
	type datos struct {
		Error string
		Hecho bool
	}
	r.Get("/cuenta/clave", func(w http.ResponseWriter, r *http.Request) {
		web.Render(w, http.StatusOK, "cuenta-clave", datos{})
	})
	r.Post("/cuenta/clave", func(w http.ResponseWriter, r *http.Request) {
		u := Cuenta(r)
		r.ParseForm()
		actual, nueva := r.PostForm.Get("actual"), r.PostForm.Get("nueva")
		if _, err := a.Login(u.Name, actual, clientIP(r)); err != nil {
			a.secLog(r, "fallo", u.Name, "contraseña actual incorrecta al cambiarla")
			web.Render(w, http.StatusOK, "cuenta-clave", datos{Error: "La contraseña actual no es correcta"})
			return
		}
		if err := a.SetUser(u.Name, u.Role, nueva, false); err != nil {
			web.Render(w, http.StatusOK, "cuenta-clave", datos{Error: err.Error()})
			return
		}
		a.secLog(r, "clave", u.Name, "cambió su contraseña")
		tok, _ := a.Login(u.Name, nueva, clientIP(r)) // SetUser cerró todas sus sesiones: una nueva aquí
		setSessionCookie(w, r, tok, int(sessionTTL.Seconds()))
		web.Render(w, http.StatusOK, "cuenta-clave", datos{Hecho: true})
	})
}

// datos de la ventana de una cuenta
type ventanaUsuario struct {
	Nuevo           bool
	Usuario, Perfil string
	Error           string
	Yo              bool
	Perfiles        [][2]string
}

var listaPerfiles = [][2]string{{"admin", "Administrador"}, {"operador", "Operador"}, {"consulta", "Consulta"}}

// RutasUsuariosUI (solo admin): Configuración → Usuarios.
func (a *Auth) RutasUsuariosUI(r chi.Router) {
	r.Get("/configuracion/usuarios/nueva", func(w http.ResponseWriter, r *http.Request) {
		web.Render(w, http.StatusOK, "cfg-usuario-ventana", ventanaUsuario{Nuevo: true, Perfil: "consulta", Perfiles: listaPerfiles})
	})
	r.Get("/configuracion/usuarios/editar", func(w http.ResponseWriter, r *http.Request) {
		n := r.URL.Query().Get("u")
		for _, u := range a.Users() {
			if u.Name == n {
				web.Render(w, http.StatusOK, "cfg-usuario-ventana", ventanaUsuario{Usuario: u.Name, Perfil: u.Role,
					Yo: u.Name == Cuenta(r).Name, Perfiles: listaPerfiles})
				return
			}
		}
		http.Error(w, "no existe la cuenta", 404)
	})
	r.Post("/configuracion/usuarios", func(w http.ResponseWriter, r *http.Request) {
		me := Cuenta(r)
		r.ParseForm()
		f := r.PostForm
		nuevo := f.Get("nuevo") == "1"
		usuario, perfil, clave := strings.ToLower(strings.TrimSpace(f.Get("usuario"))), f.Get("perfil"), f.Get("clave")
		if err := a.SetUser(usuario, perfil, clave, nuevo); err != nil {
			// el error vuelve a la ventana, no a la tabla
			w.Header().Set("HX-Retarget", "#modal")
			w.Header().Set("HX-Reswap", "innerHTML")
			web.Render(w, http.StatusOK, "cfg-usuario-ventana", ventanaUsuario{Nuevo: nuevo, Usuario: usuario, Perfil: perfil,
				Error: err.Error(), Yo: usuario == me.Name, Perfiles: listaPerfiles})
			return
		}
		verbo := "cambió"
		if nuevo {
			verbo = "creó"
		}
		det := fmt.Sprintf("%s la cuenta %s (%s)", verbo, usuario, perfil)
		if clave != "" && !nuevo {
			det += " y su contraseña"
		}
		a.ev.AddEvent("info", me.Name+" "+det)
		a.secLog(r, "cuenta", me.Name, det)
		aviso := "Cuenta " + usuario + " guardada."
		if nuevo {
			aviso = "Cuenta " + usuario + " creada."
		}
		web.Render(w, http.StatusOK, "cfg-usuarios-y-cerrar", a.DatosUsuarios(me.Name, aviso))
	})
	r.Delete("/configuracion/usuarios", func(w http.ResponseWriter, r *http.Request) {
		me, n := Cuenta(r), r.URL.Query().Get("u")
		aviso := "Cuenta " + n + " borrada."
		if n == me.Name {
			aviso = "No puedes borrar tu propia cuenta."
		} else if err := a.DeleteUser(n); err != nil {
			aviso = err.Error()
		} else {
			a.ev.AddEvent("info", fmt.Sprintf("%s borró la cuenta %s", me.Name, n))
			a.secLog(r, "cuenta", me.Name, "borró la cuenta "+n)
		}
		web.Render(w, http.StatusOK, "cfg-usuarios-y-cerrar", a.DatosUsuarios(me.Name, aviso))
	})
}
