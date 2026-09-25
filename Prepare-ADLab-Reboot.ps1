[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$run = Join-Path $root '.run'
New-Item -ItemType Directory -Path $run -Force | Out-Null
$computer = Get-CimInstance Win32_ComputerSystem
if ($computer.Name -ne 'DC01' -or $computer.Domain -ne 'adlab.test') {
    throw 'Требуется именно тестовая ВМ DC01 в домене adlab.test.'
}
if ($computer.DomainRole -ne 3 -or (Get-Service NTDS).Status -ne 'Stopped') {
    throw 'Этот шаг нужен только после повышения DC01, до завершающей перезагрузки.'
}

if ($PSVersionTable.PSVersion.Major -le 5) {
    Add-Type -AssemblyName System.Security
} else {
    Add-Type -AssemblyName System.Security.Cryptography.ProtectedData
}
function New-StrongPassword {
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ('Aa1!' + [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','x').Replace('/','y'))
}
$secrets = @{ LabPassword = (New-StrongPassword); ScannerPassword = (New-StrongPassword) }
$json = $secrets | ConvertTo-Json -Compress
$encrypted = [Security.Cryptography.ProtectedData]::Protect(
    [Text.Encoding]::UTF8.GetBytes($json), $null,
    [Security.Cryptography.DataProtectionScope]::LocalMachine)
$secretPath = Join-Path $run 'ad-secrets.bin'
[IO.File]::WriteAllBytes($secretPath, $encrypted)
& icacls.exe $secretPath /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Не удалось ограничить доступ к файлу паролей.' }

$env:DOTNET_CLI_HOME = Join-Path $run 'dotnet'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
dotnet user-secrets set 'ActiveDirectory:Username' 'ADLAB\svc_ira_scanner' --project (Join-Path $root 'src\IdentityRiskAnalyzer.Web') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Не удалось настроить имя scanner в User Secrets.' }
dotnet user-secrets set 'ActiveDirectory:Password' $secrets.ScannerPassword --project (Join-Path $root 'src\IdentityRiskAnalyzer.Web') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Не удалось настроить пароль scanner в User Secrets.' }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $root 'Complete-ADLab.ps1')) -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -StartWhenAvailable
Register-ScheduledTask -TaskName 'IRA-Complete-ADLab' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Write-Host 'Подготовлено: после перезагрузки задача IRA-Complete-ADLab создаст тестовые объекты AD, запустит оба сайта и выполнит сканирование.'
Write-Host 'Пароли созданы случайно и сохранены в защищённом локальном файле; в Git они не попадают.'
Write-Host 'Теперь выполните Restart-Computer -Force. После входа запустите Status-Demo.ps1 и проверьте .run\ad-lab-status.json.'
