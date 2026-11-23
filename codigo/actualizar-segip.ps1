# Actualiza solo monitoreo-segip en la Pi y lo vuelve a aplicar (pide la contraseña de redes).
Set-Location $PSScriptRoot
scp monitoreo-segip redes@192.168.10.200:/home/redes/
if ($LASTEXITCODE -ne 0) { Write-Host "Falló la copia" -ForegroundColor Red; return }
ssh -t redes@192.168.10.200 "sudo install -m 755 /home/redes/monitoreo-segip /usr/local/bin/ && rm -f /home/redes/monitoreo-segip && sudo monitoreo-segip && sudo monitoreo-segip && sudo monitoreo-segip ver"
Write-Host "== Terminado (código $LASTEXITCODE) ==" -ForegroundColor Cyan
