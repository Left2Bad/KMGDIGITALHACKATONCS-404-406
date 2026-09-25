$statePath = Join-Path $PSScriptRoot '.run\demo-processes.json'
if (-not (Test-Path $statePath)) { Write-Host 'Процессы демо не зарегистрированы.'; return }
$state = Get-Content $statePath -Raw | ConvertFrom-Json
foreach ($item in @(@($state.Identity, 'run --no-build --launch-profile http'), @($state.Radar, 'radar.cli serve'), @($state.Lab, 'lab/serve.py'))) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($item[0])" -ErrorAction SilentlyContinue
    if ($process -and $process.CommandLine -like "*$($item[1])*") {
        taskkill /PID $process.ProcessId /T /F 2>$null | Out-Null
    }
}
Remove-Item -LiteralPath $statePath -Force
Write-Host 'Демо остановлено.'
