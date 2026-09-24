# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param([Security.SecureString]$ScannerPassword)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
Assert-LabAdministrator
$domain = Assert-LabDomain
Assert-LabStructure
$scanner = Get-LabUser -SamAccountName $Lab.ScannerAccount -ExpectedParentDn $Lab.ServiceAccountsDn
if (-not $scanner) {
    if (-not $ScannerPassword) { $ScannerPassword = Read-Host 'Enter a separate scanner account password' -AsSecureString }
    if (-not $ScannerPassword) { throw 'Scanner password is required.' }
    New-ADUser -Name $Lab.ScannerAccount -SamAccountName $Lab.ScannerAccount -UserPrincipalName ("{0}@{1}" -f $Lab.ScannerAccount, $Lab.DomainName) -Path $Lab.ServiceAccountsDn -AccountPassword $ScannerPassword -Enabled $true -ChangePasswordAtLogon $false -ErrorAction Stop
    Write-LabStep OK ('Created ordinary Domain User scanner: {0}' -f $Lab.ScannerAccount)
} else {
    if ($ScannerPassword) { Set-ADAccountPassword -Identity $scanner -Reset -NewPassword $ScannerPassword -ErrorAction Stop }
    Enable-ADAccount -Identity $scanner -ErrorAction Stop
    Set-ADAccountControl -Identity $scanner -PasswordNeverExpires $false -ErrorAction Stop
    Write-LabStep SKIP ('Scanner exists in lab OU: {0}' -f $Lab.ScannerAccount)
}
$scanner = Get-LabUser -SamAccountName $Lab.ScannerAccount -ExpectedParentDn $Lab.ServiceAccountsDn
if (-not (Test-LabScannerUnprivileged -Scanner $scanner -Domain $domain)) {
    throw 'Scanner has privileged group membership. Review and remove it manually; script will not silently alter memberships.'
}
Write-LabStep OK 'Scanner is enabled and has no listed administrative group membership. Standard Domain User directory read access is used.'
