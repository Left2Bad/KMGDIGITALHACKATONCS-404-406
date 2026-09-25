[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$run = Join-Path $root '.run'
$statusPath = Join-Path $run 'ad-lab-status.json'
$logPath = Join-Path $run 'ad-lab-setup.log'
New-Item -ItemType Directory -Path $run -Force | Out-Null
Start-Transcript -Path $logPath -Append | Out-Null
$adStatus = 'failed'
$details = ''

try {
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.Name -ne 'DC01' -or $computer.Domain -ne 'adlab.test') {
        throw 'Этот скрипт предназначен только для тестовой ВМ DC01 в домене adlab.test.'
    }
    $ready = $false
    for ($i = 0; $i -lt 90; $i++) {
        if ((Get-Service NTDS).Status -eq 'Running' -and (Get-Service ADWS).Status -eq 'Running') {
            try {
                $client = New-Object Net.Sockets.TcpClient
                $client.Connect('127.0.0.1', 389)
                $client.Dispose()
                $ready = $true
                break
            } catch { if ($client) { $client.Dispose() } }
        }
        Start-Sleep -Seconds 10
    }
    if (-not $ready) { throw 'AD DS не открыл LDAP 389 за 15 минут.' }
    $computer = Get-CimInstance Win32_ComputerSystem
    if ($computer.DomainRole -ne 5) { throw 'После запуска AD DS сервер не определился как контроллер домена.' }

    if ($PSVersionTable.PSVersion.Major -le 5) {
        Add-Type -AssemblyName System.Security
    } else {
        Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
    }
    $encrypted = [IO.File]::ReadAllBytes((Join-Path $run 'ad-secrets.bin'))
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $encrypted, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $secrets = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    $labPassword = ConvertTo-SecureString $secrets.LabPassword -AsPlainText -Force
    $scannerPassword = ConvertTo-SecureString $secrets.ScannerPassword -AsPlainText -Force

    $lab = Join-Path $root 'scripts\adlab'
    & (Join-Path $lab '02-Create-LabStructure.ps1')
    & (Join-Path $lab '03-Create-LabAccounts.ps1') -DefaultUserPassword $labPassword
    & (Join-Path $lab '04-Configure-RiskScenarios.ps1') -ConfirmLabChanges
    & (Join-Path $lab '05-Create-ScannerAccount.ps1') -ScannerPassword $scannerPassword
    & (Join-Path $lab '06-Verify-Lab.ps1')

    $adStatus = 'ready'
    Write-Host 'Тестовый AD готов.'
} catch {
    $details = $_.Exception.Message
    Write-Error -Message "Ошибка подготовки AD: $details" -ErrorAction Continue
} finally {
    try {
        if (Test-Path (Join-Path $run 'ad-secrets.bin')) {
            $encrypted = [IO.File]::ReadAllBytes((Join-Path $run 'ad-secrets.bin'))
            $plain = [Security.Cryptography.ProtectedData]::Unprotect(
                $encrypted, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
            $secrets = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
            $env:ActiveDirectory__Username = 'ADLAB\svc_ira_scanner'
            $env:ActiveDirectory__Password = $secrets.ScannerPassword
        }
        & (Join-Path $root 'Start-Demo.ps1')
        if ($adStatus -eq 'ready') {
            $scanPage = Invoke-WebRequest -Uri 'http://127.0.0.1:5207/Scans' -SessionVariable webSession -UseBasicParsing -TimeoutSec 20
            if ($scanPage.Content -notmatch 'name="__RequestVerificationToken"[^>]*value="([^"]+)"') {
                throw 'Не найден токен формы запуска AD scan.'
            }
            $token = $Matches[1]
            Invoke-WebRequest -Uri 'http://127.0.0.1:5207/Scans/Start' -Method Post -WebSession $webSession `
                -Body @{ __RequestVerificationToken = $token } -UseBasicParsing -TimeoutSec 180 | Out-Null
            $scanList = Invoke-WebRequest -Uri 'http://127.0.0.1:5207/Scans' -UseBasicParsing -TimeoutSec 20
            if ($scanList.Content -notmatch '<td>Completed</td>') {
                throw 'Скан завершился без статуса Completed. Откройте http://127.0.0.1:5207/Scans.'
            }
            Write-Host 'Первый скан Active Directory выполнен.'
        }
    } catch {
        $details = ($details + ' Запуск сайтов или первого скана: ' + $_.Exception.Message).Trim()
        $adStatus = 'failed'
        Write-Error -Message $details -ErrorAction Continue
    }
    [pscustomobject]@{ Status = $adStatus; Details = $details; UpdatedAt = (Get-Date).ToUniversalTime().ToString('o') } |
        ConvertTo-Json | Set-Content -Path $statusPath -Encoding UTF8
    Stop-Transcript | Out-Null
}
if ($adStatus -ne 'ready') { exit 1 }
