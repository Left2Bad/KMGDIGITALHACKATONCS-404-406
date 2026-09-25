$statePath = Join-Path $PSScriptRoot '.run\demo-processes.json'
$adStatusPath = Join-Path $PSScriptRoot '.run\ad-lab-status.json'
if (Test-Path $adStatusPath) {
    $ad = Get-Content $adStatusPath -Raw | ConvertFrom-Json
    Write-Host "Тестовый AD: $($ad.Status) $($ad.Details)"
} else { Write-Host 'Тестовый AD: настройка ещё не завершена.' }
if (Test-Path $statePath) {
    $state = Get-Content $statePath -Raw | ConvertFrom-Json
    foreach ($entry in @(@('TLS lab', $state.Lab), @('Certificate Radar', $state.Radar), @('Identity Risk Analyzer', $state.Identity))) {
        $running = [bool](Get-Process -Id $entry[1] -ErrorAction SilentlyContinue)
        Write-Host "$($entry[0]): $(if ($running) { 'работает' } else { 'остановлен' }) (PID $($entry[1]))"
    }
} else { Write-Host 'Демо не запущено через Start-Demo.ps1.' }
foreach ($item in @(@('Certificate Radar', 'http://127.0.0.1:8000/'), @('Identity Risk Analyzer', 'http://127.0.0.1:5207/'))) {
    try {
        $response = Invoke-WebRequest -Uri $item[1] -UseBasicParsing -TimeoutSec 5
        Write-Host "$($item[0]) HTTP: $($response.StatusCode) — $($item[1])"
    } catch { Write-Host "$($item[0]) HTTP: недоступен — $($item[1])" }
}
