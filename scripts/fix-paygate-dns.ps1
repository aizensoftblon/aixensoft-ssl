# Ejecutar PowerShell como Administrador — añade PayGate al archivo hosts si tu DNS lo bloquea.
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$ips = @(
  "104.26.4.61",
  "104.26.5.61"
)
$names = @(
  "api.paygate.to",
  "checkout.paygate.to"
)
$block = @"
# Aixensoft SSL — PayGate (añadido $(Get-Date -Format yyyy-MM-dd))
"@

foreach ($ip in $ips) {
  foreach ($name in $names) {
    $line = "$ip $name"
    if (-not (Select-String -Path $hostsPath -Pattern ([regex]::Escape($name)) -Quiet)) {
      $block += "`n$line"
    }
  }
}

if ($block -match "paygate") {
  Add-Content -Path $hostsPath -Value $block
  Write-Host "Hosts actualizado. Reinicia el navegador y prueba de nuevo el checkout."
} else {
  Write-Host "PayGate ya estaba en hosts; no hubo cambios."
}