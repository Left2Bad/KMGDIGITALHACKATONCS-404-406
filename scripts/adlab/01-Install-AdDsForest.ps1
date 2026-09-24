# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param(
    [switch]$ConfirmLabInstall,
    [Security.SecureString]$DsrmPassword
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
if (-not $ConfirmLabInstall) { throw 'Pass -ConfirmLabInstall after verifying this is a disposable, isolated VM.' }
Assert-LabAdministrator
$os = Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1) { throw 'Windows Server is required.' }
if ($env:COMPUTERNAME -ine $Lab.DcName) { throw ('Rename the VM to {0} and reboot first.' -f $Lab.DcName) }
if (Get-Service NTDS -ErrorAction SilentlyContinue) { throw 'AD DS is already installed. Do not run forest installation twice.' }
if (-not $DsrmPassword) { $DsrmPassword = Read-Host 'Enter DSRM password for the isolated lab' -AsSecureString }
if (-not $DsrmPassword) { throw 'DSRM password is required.' }
Write-LabStep OK ('Installing AD DS and DNS for {0}. Promotion will reboot this VM.' -f $Lab.DomainName)
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop | Out-Null
Import-Module ADDSDeployment -ErrorAction Stop
Install-ADDSForest -DomainName $Lab.DomainName -DomainNetbiosName $Lab.NetbiosName -SafeModeAdministratorPassword $DsrmPassword -InstallDns -Force -ErrorAction Stop
