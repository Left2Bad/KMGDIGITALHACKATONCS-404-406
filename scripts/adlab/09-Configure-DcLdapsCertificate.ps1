# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
. (Join-Path $PSScriptRoot 'LdapsCertificateChecks.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
Assert-LabAdministrator
$null = Assert-LabDomain
Assert-LabStructure
$caName = 'ADLAB-Lab-Root-CA'
$configured = Get-Item ('HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\{0}' -f $caName) -ErrorAction SilentlyContinue
if (-not $configured) { throw 'Expected isolated lab CA is not configured. Run 08 first.' }
if ((Get-Service CertSvc -ErrorAction Stop).Status -ne 'Running') { throw 'CertSvc is not running.' }

$reports = @(Get-LabLdapsCertificateReport -DnsName $Lab.Server)
$suitable = @($reports | Where-Object { $_.Hostname -and $_.ServerAuthEku -and $_.PrivateKey -and $_.ValidDates -and $_.Chain })
if ($suitable.Count -gt 1) { Write-Warning 'Multiple suitable LDAPS certificates exist. AD DS certificate selection should be reviewed.' }
if ($suitable.Count -gt 0) {
    Write-LabStep SKIP ('Suitable DC certificate already exists: {0}' -f $suitable[0].Thumbprint)
    return
}
if ($reports.Count -gt 0) {
    throw 'A potential LDAPS certificate exists but fails hostname, EKU, private-key, date, or chain checks. Resolve it before requesting another certificate.'
}

Import-Module ADCSAdministration -ErrorAction Stop
$templateName = 'DomainControllerAuthentication'
$published = @(Get-CATemplate | Where-Object { $_.Name -eq $templateName -or $_.ObjectName -eq $templateName })
if ($published.Count -eq 0) {
    Add-CATemplate -Name $templateName -Force -ErrorAction Stop | Out-Null
    Write-LabStep OK ("Published certificate template: $templateName")
} else { Write-LabStep SKIP ("Certificate template is published: $templateName") }

$enrollment = & certreq.exe -enroll -machine $templateName 2>&1
if ($LASTEXITCODE -ne 0) { throw ('Machine certificate enrollment failed: {0}' -f ($enrollment -join ' ')) }
$suitable = @(Get-LabLdapsCertificateReport -DnsName $Lab.Server | Where-Object { $_.Hostname -and $_.ServerAuthEku -and $_.PrivateKey -and $_.ValidDates -and $_.Chain })
if ($suitable.Count -eq 0) { throw 'Enrollment returned, but no fully suitable DC certificate was found in Local Computer\Personal.' }
Write-LabStep OK ('DC certificate enrolled in Local Computer\Personal: {0}' -f $suitable[0].Thumbprint)
Write-Warning 'Restart DC01 manually if LDAPS does not pick up the new certificate, then run 10-Verify-Ldaps.ps1.'
