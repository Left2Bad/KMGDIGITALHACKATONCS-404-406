# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param([switch]$ConfirmLabCleanup)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
if (-not $ConfirmLabCleanup) { throw 'Pass -ConfirmLabCleanup and confirm the exact lab name interactively.' }
Assert-LabAdministrator
$domain = Assert-LabDomain
Assert-LabStructure
$expectedRoot = 'OU=HackathonLab,DC=adlab,DC=test'
if ($Lab.RootDn -ine $expectedRoot -or $Lab.DomainName -ine 'adlab.test') {
    throw 'Cleanup target does not match the fixed isolated-lab allowlist.'
}
$typed = Read-Host 'Type adlab.test/HackathonLab to delete only lab objects'
if ($typed -cne 'adlab.test/HackathonLab') { throw 'Cleanup cancelled: confirmation did not match.' }

# Validate every deletion target before changing any memberships or policy.
$pso = Get-ADFineGrainedPasswordPolicy -Identity $Lab.LockoutPsoName -Properties Description -ErrorAction SilentlyContinue
if ($pso -and $pso.Description -cne $Lab.Marker) { throw 'Existing PSO lacks the lab marker. Refusing to remove it.' }
$ous = @(Get-ADOrganizationalUnit -SearchBase $Lab.RootDn -SearchScope Subtree -Filter * -Properties Description -ErrorAction Stop)
foreach ($ou in $ous) {
    if ($ou.DistinguishedName -ine $Lab.RootDn -and -not $ou.DistinguishedName.EndsWith(',' + $Lab.RootDn, [StringComparison]::OrdinalIgnoreCase)) {
        throw ('OU escaped lab root: {0}' -f $ou.DistinguishedName)
    }
    if ($ou.Description -cne $Lab.Marker) { throw ('OU lacks the lab marker: {0}' -f $ou.DistinguishedName) }
}

$itAdmins = Get-LabGroup -Name 'DemoITAdmins'
$direct = Get-LabUser -SamAccountName 'lab_direct_admin' -ExpectedParentDn $Lab.UsersDn
$multi = Get-LabUser -SamAccountName 'lab_multi_admin' -ExpectedParentDn $Lab.UsersDn
$scanner = Get-LabUser -SamAccountName $Lab.ScannerAccount -ExpectedParentDn $Lab.ServiceAccountsDn
$externalEdges = @(
    @{ Group = Get-ADGroup -Identity ('{0}-512' -f $domain.DomainSID.Value); Member = $itAdmins },
    @{ Group = Get-ADGroup -Identity 'S-1-5-32-551'; Member = $direct },
    @{ Group = Get-ADGroup -Identity 'S-1-5-32-551'; Member = $multi },
    @{ Group = Get-ADGroup -Identity 'S-1-5-32-549'; Member = $multi },
    @{ Group = Get-ADGroup -Identity 'S-1-5-32-573'; Member = $scanner }
)
foreach ($edge in $externalEdges) {
    if ($edge.Member -and (Test-DirectGroupMember -Group $edge.Group -Member $edge.Member)) {
        Remove-ADGroupMember -Identity $edge.Group -Members $edge.Member -Confirm:$false -ErrorAction Stop
        Write-LabStep OK ("Removed external membership: {0} -> {1}" -f $edge.Member.Name, $edge.Group.Name)
    }
}

if ($pso) {
    Remove-ADFineGrainedPasswordPolicy -Identity $pso -Confirm:$false -ErrorAction Stop
    Write-LabStep OK ('Removed lab PSO: {0}' -f $Lab.LockoutPsoName)
}

# Unprotect only OUs strictly below the verified lab root, then remove that root.
foreach ($ou in $ous) {
    Set-ADOrganizationalUnit -Identity $ou -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
}
Remove-ADOrganizationalUnit -Identity $Lab.RootDn -Recursive -Confirm:$false -ErrorAction Stop
Write-LabStep OK ('Removed only {0} and its children.' -f $Lab.RootDn)
Write-LabStep SKIP 'KDS root key, AD DS installation, domain, and VM were deliberately retained.'
