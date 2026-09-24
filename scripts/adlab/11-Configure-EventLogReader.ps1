# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param([switch]$ConfirmOptionalEventLogAccess)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')

if (-not $ConfirmOptionalEventLogAccess) {
    throw 'Pass -ConfirmOptionalEventLogAccess to grant the lab scanner optional Security Event Log read access.'
}
Assert-LabAdministrator
$domain = Assert-LabDomain
Assert-LabStructure
$scanner = Get-LabUser -SamAccountName $Lab.ScannerAccount -ExpectedParentDn $Lab.ServiceAccountsDn
if (-not $scanner) { throw 'Lab scanner account is missing.' }
if (-not (Test-LabScannerUnprivileged -Scanner $scanner -Domain $domain)) {
    throw 'Scanner has unexpected administrative membership. Refusing to continue.'
}

$readers = Get-ADGroup -Identity 'S-1-5-32-573' -Properties member -ErrorAction Stop
if ($readers.SID.Value -ne 'S-1-5-32-573') { throw 'Event Log Readers SID mismatch.' }
Write-Host 'Adding scanner to Event Log Readers for optional P1-18.'
if (@($readers.member | Where-Object { $_ -ieq $scanner.DistinguishedName }).Count -eq 0) {
    Add-ADGroupMember -Identity $readers -Members $scanner -ErrorAction Stop
    Write-LabStep OK 'Lab scanner added to Event Log Readers.'
} else {
    Write-LabStep SKIP 'Lab scanner is already a direct Event Log Readers member.'
}
Write-Host 'The scanner may need a fresh logon token. Check DC event log policy and remote Event Log firewall access separately.'
