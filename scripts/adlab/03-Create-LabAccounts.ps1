# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param([Security.SecureString]$DefaultUserPassword)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
Assert-LabAdministrator
$null = Assert-LabDomain
Assert-LabStructure

$normalUsers = @('lab_clean_user', 'lab_expired_user', 'lab_pne_user', 'lab_direct_admin', 'lab_nested_admin', 'lab_multi_admin', 'lab_locked_user')
$serviceUsers = @('svc_sql', 'svc_unconstrained', 'svc_constrained', 'svc_protocol_transition', 'svc_rbcd_source', 'svc_rbcd_target')
$missing = @($normalUsers | Where-Object { -not (Get-LabUser -SamAccountName $_ -ExpectedParentDn $Lab.UsersDn) })
$missing += @($serviceUsers | Where-Object { -not (Get-LabUser -SamAccountName $_ -ExpectedParentDn $Lab.ServiceAccountsDn) })
if ($missing.Count -gt 0 -and -not $DefaultUserPassword) {
    $DefaultUserPassword = Read-Host 'Enter a strong password for new lab test accounts' -AsSecureString
}
if ($missing.Count -gt 0 -and -not $DefaultUserPassword) { throw 'A password is required for new lab accounts.' }

foreach ($name in $normalUsers + $serviceUsers) {
    $parentDn = if ($normalUsers -contains $name) { $Lab.UsersDn } else { $Lab.ServiceAccountsDn }
    $existing = Get-LabUser -SamAccountName $name -ExpectedParentDn $parentDn
    if ($existing) {
        Write-LabStep SKIP ("User exists: $name")
    } else {
        New-ADUser -Name $name -SamAccountName $name -UserPrincipalName ("{0}@{1}" -f $name, $Lab.DomainName) -Path $parentDn -AccountPassword $DefaultUserPassword -Enabled $true -ChangePasswordAtLogon $false -ErrorAction Stop
        Write-LabStep OK ("Created user: $name")
    }
}

foreach ($name in @('DemoHelpDesk', 'DemoITAdmins', 'DemoGmsaHosts')) {
    $existing = Get-LabGroup -Name $name
    if ($existing) {
        Write-LabStep SKIP ("Group exists: $name")
    } else {
        New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -Path $Lab.GroupsDn -ErrorAction Stop | Out-Null
        Write-LabStep OK ("Created group: $name")
    }
}
