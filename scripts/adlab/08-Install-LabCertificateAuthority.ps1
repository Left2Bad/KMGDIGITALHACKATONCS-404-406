# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param([switch]$ConfirmLabCaInstall)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
if (-not $ConfirmLabCaInstall) { throw 'Pass -ConfirmLabCaInstall only on the isolated single-DC lab VM.' }
Assert-LabAdministrator
$null = Assert-LabDomain
Assert-LabStructure
$caName = 'ADLAB-Lab-Root-CA'
$configurationPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
$configuredNames = if (Test-Path $configurationPath) { @(Get-ChildItem $configurationPath | Select-Object -ExpandProperty PSChildName) } else { @() }
if ($configuredNames.Count -gt 0) {
    if ($configuredNames.Count -ne 1 -or $configuredNames[0] -cne $caName) {
        throw ('A different CA configuration already exists: {0}. Refusing to create or replace it.' -f ($configuredNames -join ', '))
    }
    $service = Get-Service CertSvc -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw 'Expected lab CA is configured but CertSvc is not running. Resolve this before enrollment.' }
    Write-LabStep SKIP ("Expected Enterprise Root CA already configured: $caName")
    return
}
$feature = Get-WindowsFeature ADCS-Cert-Authority -ErrorAction Stop
if (-not $feature.Installed) {
    Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools -ErrorAction Stop | Out-Null
    Write-LabStep OK 'Installed AD CS Certification Authority role service.'
} else {
    Write-LabStep SKIP 'AD CS Certification Authority role service already installed.'
}
Import-Module ADCSDeployment -ErrorAction Stop
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName $caName -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 -Force -ErrorAction Stop | Out-Null
Write-LabStep OK ("Configured isolated Enterprise Root CA: $caName")
Write-Warning 'The CA private key stays on this lab server. Export only the public root .cer for application hosts.'
