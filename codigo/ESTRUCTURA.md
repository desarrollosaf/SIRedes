# Estructura del código

Monitoreo de Red es **un solo programa en Go** que mide la red y sirve el panel. Se ordena como el
backend de referencia: cada parte en su carpeta, con la seguridad aparte y el HTML en plantillas.

```
codigo/
  main.go            arranque: configuración, base, monitor, servidor
  servidor.go        rutas con chi (grupos: públicas, con sesión, solo admin) y HTTPS
  middleware/        seguridad para TODAS las peticiones (cabeceras, límites, CSRF, registro)
  app/
    cuentas/         cuentas, sesiones, perfiles, bitácora de seguridad y pantalla de entrada
  web/               lo que ve el navegador (va dentro del programa)
    templates/       HTML que arma Go con html/template (escapa todo solo) + htmx
    static/          archivos tal cual: app.css, htmx.min.js
    index.html       panel viejo (solo el Resumen, JavaScript propio) mientras se migra
  *.go (resto)       monitor, base, segmentos, SNMP, internet, avisos… (por mover a app/)
  install.sh …       instalación en la Pi (por mover a despliegue/)
```

## Front: Go + htmx (sin Alpine, sin Node)

- Go arma el HTML con `html/template` (escapa todo dato: un nombre de equipo con código no se ejecuta).
- htmx (un archivo, dentro del programa) pide a Go un pedazo de HTML y lo pone en su lugar:
  `hx-post`, `hx-get`, `hx-target`, `hx-trigger="every 5s"`. Sin JavaScript propio.
- Sin nada cargado de internet: el panel funciona aunque se caiga el internet.
- Pantallas migradas van con CSP estricta (`web.CSPEstricta`): sin JavaScript ni estilos en línea.

## Seguridad (orden de las capas)

Recuperar → Registro → Cabeceras → Tamaño (64 KiB) → Límite por IP (30/s; 2/s en entrada)
→ Mismo origen (CSRF) → gzip → rutas. Con sesión: `Sesion` → `PuedeCambiar` (GET cualquiera,
cambios Operador) → `SoloAdmin` (cuentas y bitácora). La API v1 (`/api/v1/*`) usa su propio token.

## Migración (una pantalla por versión)

| Pantalla | Estado |
| :--- | :--- |
| Entrada (`/login`) | Go + htmx (v2.15) |
| Configuración | Go + htmx (v2.16) |
| Dispositivos | Go + htmx (v2.20) |
| Router | Go + htmx (v2.18) |
| Eventos | Go + htmx (v2.18) |
| Internet y servicios | Go + htmx (v2.19) |
| Resumen | pendiente |

Al mover cada pantalla, su lógica de Go pasa a `app/<módulo>/` (handler, servicio, datos).
Cuando ya no quede `index.html`, la CSP estricta aplica a todo.

## Pruebas

```
go test ./app/... ./middleware        # en Windows
GOOS=linux go vet ./...               # todo el programa (usa partes de Linux)
```
