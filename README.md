# SIRedes · Monitoreo de Red

Monitor de red para una **Raspberry Pi**: descubre los equipos de cada segmento (ARP y ping),
vigila cable e internet por segmento, lee routers por SNMP y avisa cuando algo falla.
Se usa desde el navegador en `http://IP-DE-LA-PI:5000`.

- **Un solo programa en Go** (con el panel dentro). Base de datos SQLite en la Pi.
- **Rutas con chi** y capas de seguridad: cabeceras (CSP, X-Frame, nosniff…), límite por IP,
  tamaño de petición, protección CSRF, registro y HTTPS opcional.
- **Cuentas** con perfiles Administrador / Operador / Consulta y bitácora de seguridad.
- **Pantallas con Go + htmx** (plantillas `html/template`, sin Node ni frameworks); el panel
  anterior se va migrando pantalla por pantalla.
- **API JSON v1** con token para otros sistemas y avisos por webhook (tickets).

Estructura y plan de migración: [`codigo/ESTRUCTURA.md`](codigo/ESTRUCTURA.md).
Instalación en la Pi: [`LEEME.txt`](LEEME.txt).

## Compilar

```
cd codigo
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o monitoreo-arm64 .
go test ./...
```

En Windows el programa también corre (sin ARP) para revisar pantallas:
`go run . -port 8099 -subnet 127.0.0.0/30`.

> Las direcciones IP de los ejemplos y scripts son de ejemplo (`192.168.10.x`).
