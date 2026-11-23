@echo off
cd /d "%~dp0"
ssh -o BatchMode=yes -o ConnectTimeout=5 redes@192.168.10.200 "true" 2>nul
if errorlevel 1 (
  echo == 1/3 Guardando la llave en la Pi: escribe la contrasena de redes ==
  type "%USERPROFILE%\.ssh\id_ed25519.pub" | ssh redes@192.168.10.200 "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
)
echo == 2/3 Copiando ==
scp monitoreo-arm64 install.sh monitoreo-ip monitoreo-autoip redes@192.168.10.200:/home/redes/ || goto fallo
echo == 3/3 Instalando: escribe la contrasena de sudo ==
ssh -t redes@192.168.10.200 "cd /home/redes && chmod +x install.sh monitoreo-* && sudo ./install.sh && rm -f install.sh monitoreo-arm64 monitoreo-ip monitoreo-autoip" || goto fallo
echo == LISTO ==
goto fin
:fallo
echo == FALLO ==
:fin
