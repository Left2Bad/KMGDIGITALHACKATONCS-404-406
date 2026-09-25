# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
$domain = Assert-LabDomain
Assert-LabStructure
$results = New-Object 'System.Collections.Generic.List[object]'

function Add-Check {
    param([string]$Scenario, [string]$Object, [scriptblock]$Predicate)
    try {
        $passed = & $Predicate
        $status = if ($passed) { 'OK' } else { 'FAIL' }
        $details = if ($passed) { '' } else { 'Expected AD property or membership is missing.' }
    } catch {
        $status = 'FAIL'
        $details = $_.Exception.Message
    }
    $results.Add([pscustomobject]@{ Scenario = $Scenario; Object = $Object; Status = $status; Details = $details })
}

function Get-CheckedUser {
    param([string]$Name, [switch]$Service)
    $parent = if ($Service) { $Lab.ServiceAccountsDn } else { $Lab.UsersDn }
    $user = Get-LabUser -SamAccountName $Name -ExpectedParentDn $parent
    if (-not $user) { throw "Missing lab user: $Name" }
    return (Get-ADUser -Identity $user -Properties Enabled, PasswordNeverExpires, AccountExpirationDate, ServicePrincipalName, TrustedForDelegation, TrustedToAuthForDelegation, LockedOut, 'msDS-User-Account-Control-Computed', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity')
}

Add-Check 'Clean user' 'lab_clean_user' {
    $u = Get-CheckedUser 'lab_clean_user'
    $u.Enabled -and -not $u.PasswordNeverExpires -and @($u.ServicePrincipalName).Count -eq 0 -and -not $u.TrustedForDelegation -and -not $u.TrustedToAuthForDelegation -and (Test-LabScannerUnprivileged -Scanner $u -Domain $domain)
}
Add-Check 'Expired' 'lab_expired_user' {
    $u = Get-CheckedUser 'lab_expired_user'
    $u.Enabled -and $u.AccountExpirationDate -and $u.AccountExpirationDate -lt (Get-Date)
}
Add-Check 'PasswordNeverExpires' 'lab_pne_user' {
    (Get-CheckedUser 'lab_pne_user').PasswordNeverExpires
}
Add-Check 'Service + PNE' 'svc_sql' {
    $u = Get-CheckedUser 'svc_sql' -Service
    $u.PasswordNeverExpires -and @($u.ServicePrincipalName | Where-Object { $_ -ieq ("MSSQLSvc/sql01.{0}:1433" -f $Lab.DomainName) }).Count -eq 1
}
Add-Check 'Direct privilege' 'lab_direct_admin' {
    Test-DirectGroupMember -Group (Get-ADGroup -Identity 'S-1-5-32-551') -Member (Get-CheckedUser 'lab_direct_admin')
}
Add-Check 'Nested privilege' 'lab_nested_admin' {
    $helpDesk = Get-LabGroup 'DemoHelpDesk'
    $itAdmins = Get-LabGroup 'DemoITAdmins'
    $domainAdmins = Get-ADGroup -Identity ('{0}-512' -f $domain.DomainSID.Value)
    $helpDesk -and $itAdmins -and
    (Test-DirectGroupMember -Group $helpDesk -Member (Get-CheckedUser 'lab_nested_admin')) -and
    (Test-DirectGroupMember -Group $itAdmins -Member $helpDesk) -and
    (Test-DirectGroupMember -Group $domainAdmins -Member $itAdmins)
}
Add-Check 'Multiple privilege' 'lab_multi_admin' {
    $u = Get-CheckedUser 'lab_multi_admin'
    (Test-DirectGroupMember -Group (Get-ADGroup -Identity 'S-1-5-32-551') -Member $u) -and
    (Test-DirectGroupMember -Group (Get-ADGroup -Identity 'S-1-5-32-549') -Member $u)
}
Add-Check 'Unconstrained' 'svc_unconstrained' {
    $u = Get-CheckedUser 'svc_unconstrained' -Service
    $u.TrustedForDelegation -and @($u.ServicePrincipalName).Count -gt 0
}
Add-Check 'Constrained' 'svc_constrained' {
    $u = Get-CheckedUser 'svc_constrained' -Service
    @($u.ServicePrincipalName).Count -gt 0 -and
    @($u.'msDS-AllowedToDelegateTo' | Where-Object { $_ -ieq ("HTTP/app01.{0}" -f $Lab.DomainName) }).Count -eq 1 -and
    -not $u.TrustedToAuthForDelegation
}
Add-Check 'Protocol transition' 'svc_protocol_trans' {
    $u = Get-CheckedUser 'svc_protocol_trans' -Service
    $u.TrustedToAuthForDelegation -and
    @($u.'msDS-AllowedToDelegateTo' | Where-Object { $_ -ieq ("HTTP/app01.{0}" -f $Lab.DomainName) }).Count -eq 1
}
Add-Check 'RBCD' 'svc_rbcd_target' {
    $u = Get-CheckedUser 'svc_rbcd_target' -Service
    $source = Get-CheckedUser 'svc_rbcd_source' -Service
    $rbcd = $u.'msDS-AllowedToActOnBehalfOfOtherIdentity'
    $allowed = @(Get-ADUser -Identity $u -Properties PrincipalsAllowedToDelegateToAccount | Select-Object -ExpandProperty PrincipalsAllowedToDelegateToAccount)
    $rbcd -and @($allowed | Where-Object {
        ($_ -is [string] -and $_ -ieq $source.DistinguishedName) -or
        ($_.DistinguishedName -ieq $source.DistinguishedName)
    }).Count -gt 0
}
Add-Check 'Locked' 'lab_locked_user' {
    $u = Get-CheckedUser 'lab_locked_user'
    $pso = Get-ADUserResultantPasswordPolicy -Identity $u
    $u.LockedOut -and (($u.'msDS-User-Account-Control-Computed' -band 0x10) -ne 0) -and $pso.Name -ieq $Lab.LockoutPsoName
}
Add-Check 'gMSA' $Lab.GmsaName {
    $gmsa = Get-ADServiceAccount -Identity $Lab.GmsaName -Properties objectClass, DistinguishedName
    $gmsa.DistinguishedName -ieq ('CN={0},{1}' -f $Lab.GmsaName, $Lab.ServiceAccountsDn) -and @($gmsa.objectClass | Where-Object { $_ -ieq 'msDS-GroupManagedServiceAccount' }).Count -gt 0
}
Add-Check 'Scanner' $Lab.ScannerAccount {
    $u = Get-LabUser -SamAccountName $Lab.ScannerAccount -ExpectedParentDn $Lab.ServiceAccountsDn
    $u = Get-ADUser -Identity $u -Properties Enabled, PasswordNeverExpires
    $u.Enabled -and -not $u.PasswordNeverExpires -and (Test-LabScannerUnprivileged -Scanner $u -Domain $domain)
}

$results | Format-Table -Property Scenario, Object, Status, Details -AutoSize -Wrap
$failures = @($results | Where-Object { $_.Status -ne 'OK' })
if ($failures.Count -gt 0) { throw ("Lab verification failed: {0} of {1} scenarios." -f $failures.Count, $results.Count) }
Write-LabStep OK ("Verified {0} scenarios against actual AD properties." -f $results.Count)
