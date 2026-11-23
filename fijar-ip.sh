#!/bin/bash
# Deja la IP del cable FIJA (sin IP automática). Uso: sudo ./fijar-ip.sh 192.168.10.200 192.168.10.254
IP=${1:-192.168.10.200}
GW=${2:-192.168.10.254}
mkdir -p /etc/monitoreo
echo "MODE=manual" > /etc/monitoreo/ip.conf
CON=$(nmcli -g GENERAL.CONNECTION device show eth0)
[ -n "$CON" ] || CON=netplan-eth0
nmcli con mod "$CON" ipv4.method manual ipv4.addresses "$IP/24" ipv4.gateway "$GW" ipv4.dns "8.8.8.8 1.1.1.1"
echo "IP fija: $IP (puerta $GW). IP automática apagada."
echo "La conexión se va a cortar; entra después a http://$IP:5000"
nohup sh -c "sleep 3; nmcli con up '$CON'; sleep 5; systemctl restart monitoreo-nombre" >/dev/null 2>&1 &
