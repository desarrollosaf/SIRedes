# Copia e instala la versión compilada en la Pi (pide la contraseña de redes).
Set-Location $PSScriptRoot
Write-Host "== Copiando a la Pi ==" -ForegroundColor Cyan
scp monitoreo-arm64 install.sh monitoreo-ip monitoreo-autoip monitoreo-segip redes@192.168.10.200:/home/redes/
if ($LASTEXITCODE -ne 0) { Write-Host "Falló la copia" -ForegroundColor Red; return }
Write-Host "== Instalando ==" -ForegroundColor Cyan
ssh -t redes@192.168.10.200 "cd /home/redes && chmod +x install.sh monitoreo-* && sudo ./install.sh && rm -f install.sh monitoreo-arm64 monitoreo-ip monitoreo-autoip monitoreo-segip && sudo monitoreo-segip ver"
Write-Host "== Terminado (código $LASTEXITCODE) ==" -ForegroundColor Cyan
