#!/bin/bash
# Instalador de Monitoreo de Red para Raspberry Pi
# Uso:  sudo ./install.sh
set -e

NAME=monitoreo
PORT="${PORT:-5000}"
DIR=/opt/$NAME

if [ "$EUID" -ne 0 ]; then
  echo "Ejecuta con sudo:  sudo ./install.sh"; exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
  aarch64|arm64) BIN=$NAME-arm64 ;;
  armv7l|armv6l) BIN=$NAME-armv7 ;;
  x86_64)        BIN=$NAME-amd64 ;;
  *) echo "Arquitectura no soportada: $ARCH"; exit 1 ;;
esac

cd "$(dirname "$0")"
if [ ! -f "$BIN" ]; then
  echo "No encuentro el archivo $BIN en esta carpeta."; exit 1
fi

echo "==> Arquitectura $ARCH, usando $BIN"
systemctl stop $NAME 2>/dev/null || true

# --- cambio de nombre: netmonitor -> monitoreo (se conservan los datos) ---
if [ -f /etc/systemd/system/netmonitor.service ] || [ -d /opt/netmonitor ]; then
  echo "==> Pasando la instalación anterior (netmonitor) a $NAME"
  systemctl stop netmonitor 2>/dev/null || true
  systemctl disable netmonitor 2>/dev/null || true
  rm -f /etc/systemd/system/netmonitor.service
  if [ -d /opt/netmonitor ] && [ ! -e "$DIR/data.db" ]; then
    mkdir -p "$DIR"
    # base de datos (data.db, -wal, -shm) y respaldos json
    for f in /opt/netmonitor/data*; do
      if [ -e "$f" ]; then mv "$f" "$DIR/"; fi
    done
  fi
  rm -rf /opt/netmonitor
  id netmonitor >/dev/null 2>&1 && userdel netmonitor 2>/dev/null || true
  systemctl daemon-reload
fi

id $NAME >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin $NAME
mkdir -p "$DIR"
install -m 755 "$BIN" "$DIR/$NAME"
chown -R $NAME:$NAME "$DIR"

# comandos de IP:  sudo monitoreo-ip  (a mano)  y  monitoreo-autoip (automática)
for f in monitoreo-ip monitoreo-autoip monitoreo-segip; do
  if [ -f "$f" ]; then install -m 755 "$f" /usr/local/bin/$f; fi
done
mkdir -p /etc/monitoreo
# API v1 (sistemas externos, p. ej. React): token propio, solo lo lee root y el servicio
if [ ! -f /etc/monitoreo/api.conf ]; then
  cat > /etc/monitoreo/api.conf <<EOF
MONITOREO_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
# Dominios que pueden llamar la API desde el navegador (coma), ej. https://panel.midominio.com
MONITOREO_CORS=
EOF
fi
# avisos al sistema de tickets (se agregan a instalaciones viejas sin tocar lo que ya tengan)
if ! grep -q '^MONITOREO_WEBHOOK_URL=' /etc/monitoreo/api.conf; then
  cat >> /etc/monitoreo/api.conf <<EOF
# Avisos al sistema de tickets (vacío = apagado). Tras cambiarlo: sudo systemctl restart monitoreo
MONITOREO_WEBHOOK_URL=
MONITOREO_WEBHOOK_TOKEN=
# Segundos que la falla debe seguir sin interrupción antes del ticket, y horario de avisos por segmento
MONITOREO_WEBHOOK_CONFIRMAR=180
MONITOREO_WEBHOOK_HORARIO=9-18
EOF
fi
chown root:$NAME /etc/monitoreo/api.conf
chmod 640 /etc/monitoreo/api.conf
# Router por SNMP (opcional, solo lectura). Sin SNMP_IP queda apagado. No se pisa si ya existe.
if [ ! -f /etc/monitoreo/snmp.conf ]; then
  cat > /etc/monitoreo/snmp.conf <<'EOF'
# Lectura del router por SNMP (solo lectura). Vacío = apagado.
# Tras cambiarlo: sudo systemctl restart monitoreo
# IP del router y nombre que se verá en el panel
SNMP_IP=
SNMP_NOMBRE=Router
# Versión: 3 (recomendada) o 2c
SNMP_VERSION=3
SNMP_PUERTO=161
# Para SNMP v3 (usuario de solo lectura que sistemas permita para la IP de la Pi)
SNMP_USUARIO=
SNMP_AUTH_PROTO=SHA
SNMP_AUTH_CLAVE=
SNMP_PRIV_PROTO=AES
SNMP_PRIV_CLAVE=
# Para SNMP v2c, en lugar de lo anterior
SNMP_COMUNIDAD=
# Interfaz de la que se toma el tráfico del resumen (vacío = la más usada), ej. ge-0/0/0
SNMP_INTERFAZ_PRINCIPAL=
EOF
fi
chown root:$NAME /etc/monitoreo/snmp.conf
chmod 640 /etc/monitoreo/snmp.conf
# IP automática: activada por omisión; IPMODE=manual la apaga (sudo IPMODE=manual ./install.sh)
if [ -n "$IPMODE" ]; then
  echo "MODE=$IPMODE" > /etc/monitoreo/ip.conf
elif [ ! -f /etc/monitoreo/ip.conf ]; then
  echo "MODE=manual" > /etc/monitoreo/ip.conf   # IP fija por omisión (decisión del usuario)
fi

# IP automática: al prender y cada 5 minutos
cat > /etc/systemd/system/monitoreo-autoip.service <<EOF
[Unit]
Description=Monitoreo de Red - IP automática del cable
After=NetworkManager.service
Wants=NetworkManager.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitoreo-autoip
EOF
cat > /etc/systemd/system/monitoreo-autoip.timer <<EOF
[Unit]
Description=Monitoreo de Red - revisar la IP del cable

[Timer]
OnBootSec=20s
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

# Opción A: IP de prueba en cada segmento (lista en /etc/monitoreo/segip.conf; no se pisa si ya existe)
command -v arping >/dev/null || apt-get install -y iputils-arping || true
if [ -f segip.conf ] && [ ! -f /etc/monitoreo/segip.conf ]; then install -m 644 segip.conf /etc/monitoreo/segip.conf; fi
cat > /etc/systemd/system/monitoreo-segip.service <<EOF
[Unit]
Description=Monitoreo de Red - IPs de prueba por segmento
After=NetworkManager.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/monitoreo-segip
TimeoutStartSec=10min
EOF
cat > /etc/systemd/system/monitoreo-segip.timer <<EOF
[Unit]
Description=Monitoreo de Red - revisar IPs de prueba por segmento

[Timer]
OnBootSec=30s
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

# nombre fijo en la red: http://monitoreo.local:5000
command -v avahi-publish >/dev/null || apt-get install -y avahi-utils || true
cat > /etc/systemd/system/monitoreo-nombre.service <<EOF
[Unit]
Description=Monitoreo de Red - nombre monitoreo.local
After=avahi-daemon.service network-online.target
Wants=avahi-daemon.service

[Service]
ExecStart=/usr/local/bin/monitoreo-autoip nombre
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

# asegurar que existan ping e ip
command -v ping >/dev/null || apt-get install -y iputils-ping
command -v ip   >/dev/null || apt-get install -y iproute2
# base de fabricantes por MAC (si no hay internet, se sigue sin ella)
[ -f /usr/share/ieee-data/oui.txt ] || apt-get install -y ieee-data || true

cat > /etc/systemd/system/$NAME.service <<EOF
[Unit]
Description=Monitoreo de Red
After=network-online.target
Wants=network-online.target

[Service]
User=$NAME
WorkingDirectory=$DIR
ExecStart=$DIR/$NAME -port $PORT -data $DIR/data.json
Restart=always
RestartSec=5
# permiso solo para enviar consultas ARP (equipos que bloquean el ping)
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
# token y CORS de la API v1 (ver con: sudo cat /etc/monitoreo/api.conf)
EnvironmentFile=-/etc/monitoreo/api.conf
# endurecimiento: sin escalar privilegios, /usr /boot /etc de solo lectura, sin ver /home
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
# HTTPS (cuando sistemas dé el dominio y su certificado): quita el # de estas líneas.
# El panel queda en https://DOMINIO:5443 y el puerto 5000 redirige ahí.
#Environment=MONITOREO_TLS_CERT=/etc/monitoreo/tls.crt
#Environment=MONITOREO_TLS_KEY=/etc/monitoreo/tls.key
#Environment=MONITOREO_HTTPS_PORT=5443

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $NAME
if grep -q '^MODE=auto' /etc/monitoreo/ip.conf; then
  systemctl enable --now monitoreo-autoip.timer
else
  systemctl disable --now monitoreo-autoip.timer 2>/dev/null || true
fi
systemctl enable --now monitoreo-nombre 2>/dev/null || true
if [ -f /etc/monitoreo/segip.conf ] && command -v arping >/dev/null; then
  systemctl enable monitoreo-segip.timer
  /usr/local/bin/monitoreo-segip || true      # aplicar ya (tarda ~5 s por segmento la 1.ª vez)
  systemctl start monitoreo-segip.timer
fi

# abrir el puerto si hay firewall ufw activo
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp
fi

IP=$(hostname -I | awk '{print $1}')
echo
echo "==> Monitoreo de Red instalado y en ejecución."
echo "    Abre en cualquier equipo de tu red:  http://$IP:$PORT"
echo "                                    o:  http://monitoreo.local:$PORT"
echo "    IP: $(grep -q '^MODE=auto' /etc/monitoreo/ip.conf && echo automática || echo fija)  (sudo monitoreo-ip ver)"
echo
echo "    Ver estado:     sudo systemctl status $NAME"
echo "    Ver registro:   sudo journalctl -u $NAME -f"
echo "    Cambiar la IP:  sudo monitoreo-ip"
echo
echo "    Ya puedes borrar los archivos de instalación de esta carpeta."
