# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Proyecto

SIRedes / Monitoreo de Red: **un solo binario Go** (módulo `monitoreo`, en `codigo/`) que corre en una
Raspberry Pi, descubre equipos por segmento (ARP + ping), vigila cable/internet, lee routers por SNMP,
guarda en SQLite (`modernc.org/sqlite`, sin CGO) y sirve el panel en el puerto 5000.
Todo el texto, código y comentarios están en español; mantener ese idioma.

La versión está en `codigo/main.go` (`var version = "…"`); se sube en cada entrega.

## Comandos (desde `codigo/`)

```
# Binario para la Pi (64 bits). Para 32 bits: GOARCH=arm GOARM=7 -o monitoreo-armv7
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o monitoreo-arm64 .

go test ./app/... ./middleware          # pruebas que corren en Windows
go test -run TestNombre ./app/cuentas   # una sola prueba
GOOS=linux go vet ./...                 # revisar todo (hay archivos solo-Linux)

go run . -port 8099 -subnet 127.0.0.0/30   # correr en Windows para revisar pantallas (sin ARP)
```

Archivos con `//go:build linux` (`arp_linux.go`, `detect_linux.go`, `disco_linux.go`) tienen su
reemplazo en `otros_sistemas.go` (`!linux`); al agregar funciones de sistema, cubrir ambos lados.

Instalación en la Pi: `install.sh` (raíz) instala en `/opt/monitoreo/` como servicio systemd
`monitoreo`; los datos viven en `/opt/monitoreo/data.db` y se conservan al actualizar. Ver `LEEME.txt`.

## Arquitectura

- `main.go` arma configuración, base (`store.go`/`db.go`), el monitor (`monitor.go`, sondeos de
  segmentos, SNMP, internet) y el servidor.
- `servidor.go`: rutas con chi en grupos — públicas, con sesión, y solo admin. La API JSON
  `/api/v1/*` (`api_v1.go`) usa token propio, no sesión. `webhook.go` manda avisos (tickets).
- `middleware/`: cadena aplicada a todo, en este orden: Recuperar → Registro → Cabeceras →
  Tamaño (64 KiB) → Límite por IP (30/s; 2/s en login) → Mismo origen (CSRF) → gzip. Con sesión:
  `Sesion` → `PuedeCambiar` (GET libre; cambios requieren Operador) → `SoloAdmin`.
- `app/cuentas/`: cuentas, sesiones, perfiles (Administrador/Operador/Consulta), bitácora y login.
  Es el modelo a seguir para nuevos módulos (`app/<módulo>/` con handler, servicio y datos).
- `web/`: embebido en el binario. `templates/` (`html/template`) + `static/` (htmx, app.css);
  `index.html` es el panel viejo con JS propio, servido en `/` mientras dure la migración.

## Migración del front a Go + htmx

Se migra **una pantalla por versión**, del `index.html` viejo a plantillas + htmx:
- Sin JavaScript propio, sin Node/frameworks, nada cargado de internet (debe funcionar sin internet).
- Pantallas migradas usan CSP estricta (`web.CSPEstricta`): nada de scripts ni estilos en línea.
- Patrón (ver `ui_config.go`): `GET /pantalla` devuelve página completa; `GET /pantalla/{parte}`
  devuelve solo el fragmento para `hx-target`; POST/DELETE devuelven el fragmento actualizado.
- Al migrar, la lógica pasa a `app/<módulo>/` (Configuración hoy vive en `ui_config.go` y debe ir
  a `app/red/`). Actualizar la tabla de estado en `codigo/ESTRUCTURA.md`.

Migrado: Entrada (`/login`, v2.15) y Configuración — Segmentos, Equipos y Usuarios (v2.16).
Pendiente: Dispositivos, Router, Eventos, Internet y servicios, Resumen.

## Antes de cada commit (repo público)

Este repo es la copia pública en GitHub: nada que comprometa la seguridad de la red real.
Antes de hacer commit, revisar los archivos que entran (`git status`, `git diff --cached`) y buscar:
- IPs reales de la red (los ejemplos usan solo `192.168.10.x`), nombres de equipos, ubicaciones o personas.
- Contraseñas, tokens, comunidades SNMP, llaves o certificados (van por variables de entorno, nunca en código).
- Archivos de datos o configuración local (`*.db`, `segip.conf`, `monitoreo-data.json`, `.env`): ya
  están en `.gitignore`; si aparece uno nuevo de ese tipo, agregarlo ahí.
Si algo aparece, avisar y no hacer el commit hasta limpiarlo.
