[CmdletBinding()]
param([switch]$SkipCertificateScan)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$run = Join-Path $root '.run'
$radar = Join-Path $root 'hackatonProject2'
$python = Join-Path $radar '.venv\Scripts\python.exe'
$web = Join-Path $root 'src\IdentityRiskAnalyzer.Web'
$statePath = Join-Path $run 'demo-processes.json'
New-Item -ItemType Directory -Path $run -Force | Out-Null

function Test-TcpPort([int]$Port) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $result = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $result.AsyncWaitHandle.WaitOne(600)) { return $false }
        $client.EndConnect($result)
        return $true
    } catch { return $false }
    finally { $client.Dispose() }
}

function Wait-Port([int]$Port, [string]$Name, [int]$ProcessId) {
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-TcpPort $Port) { return }
        if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
            throw "$Name завершился. Проверьте файл .run\$Name.err.log"
        }
        Start-Sleep -Seconds 1
    }
    throw "$Name не открыл порт $Port. Проверьте .run\$Name.err.log"
}

function Start-DemoProcess([string]$Name, [string]$File, [string[]]$Arguments, [string]$Directory, [int]$Port) {
    if (Test-TcpPort $Port) { throw "Порт $Port уже занят. Запустите Status-Demo.ps1 и закройте чужой процесс." }
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -WorkingDirectory $Directory -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $run "$Name.log") -RedirectStandardError (Join-Path $run "$Name.err.log")
    try { Wait-Port $Port $Name $process.Id }
    catch {
        taskkill /PID $process.Id /T /F 2>$null | Out-Null
        throw
    }
    Write-Host "$Name запущен (PID $($process.Id), порт $Port)"
    return $process.Id
}

if (-not (Test-Path $python)) { throw "Не найден Python: $python. Выполните в hackatonProject2: uv sync" }
if (-not (Test-Path (Join-Path $web 'bin\Debug\net10.0\IdentityRiskAnalyzer.Web.dll'))) {
    throw 'Сначала выполните dotnet restore и dotnet build из корня проекта.'
}

if (Test-Path $statePath) {
    if ((Test-TcpPort 8000) -and (Test-TcpPort 5207) -and (Test-TcpPort 8443)) {
        Write-Host 'Демо уже запущено.'
        Write-Host 'Identity Risk Analyzer: http://127.0.0.1:5207/'
        Write-Host 'Certificate Radar:      http://127.0.0.1:8000/'
        return
    }
    if ((Test-TcpPort 8000) -or (Test-TcpPort 5207) -or (Test-TcpPort 8443)) {
        throw 'Найдено неполное предыдущее состояние. Запустите Stop-Demo.ps1, затем Start-Demo.ps1.'
    }
    Remove-Item -LiteralPath $statePath -Force
}

$env:DOTNET_CLI_HOME = Join-Path $run 'dotnet'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
New-Item -ItemType Directory -Path $env:DOTNET_CLI_HOME -Force | Out-Null

try {
    if (-not $SkipCertificateScan) {
        Push-Location $radar
        try {
            & $python 'lab/make_certs.py'
            if ($LASTEXITCODE -ne 0) { throw 'Не удалось создать тестовые сертификаты.' }
            & $python '-m' 'radar.cli' 'init-db'
            if ($LASTEXITCODE -ne 0) { throw 'Не удалось открыть базу Certificate Radar.' }
            & $python '-m' 'radar.cli' 'import' 'lab/targets_lab.csv'
            if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить цели Certificate Radar.' }
        } finally { Pop-Location }
    }

    $labPid = Start-DemoProcess 'tls-lab' $python @('lab/serve.py') $radar 8443
    if (-not $SkipCertificateScan) {
        Push-Location $radar
        try {
            & $python '-m' 'radar.cli' 'scan'
            if ($LASTEXITCODE -ne 0) { throw 'Скан сертификатов не завершился.' }
        } finally { Pop-Location }
    }
    $radarPid = Start-DemoProcess 'certificate-radar' $python @('-m','radar.cli','serve','--host','127.0.0.1','--port','8000') $radar 8000
    $webPid = Start-DemoProcess 'identity-risk' 'dotnet' @('run','--no-build','--launch-profile','http') $web 5207
    [pscustomobject]@{
        Lab = $labPid; Radar = $radarPid; Identity = $webPid
        LabStart = (Get-Process -Id $labPid).StartTime.ToUniversalTime().ToString('o')
        RadarStart = (Get-Process -Id $radarPid).StartTime.ToUniversalTime().ToString('o')
        IdentityStart = (Get-Process -Id $webPid).StartTime.ToUniversalTime().ToString('o')
    } |
        ConvertTo-Json | Set-Content -Path $statePath -Encoding UTF8
    Write-Host 'Identity Risk Analyzer: http://127.0.0.1:5207/'
    Write-Host 'Certificate Radar:      http://127.0.0.1:8000/'
} catch {
    foreach ($id in @($webPid, $radarPid, $labPid)) {
        if ($id) { taskkill /PID $id /T /F 2>$null | Out-Null }
    }
    throw
}
