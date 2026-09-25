# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
Assert-LabAdministrator
$null = Assert-LabDomain

$ouDefinitions = @(
    @{ Name = $Lab.RootOuName; Parent = $Lab.BaseDn; Dn = $Lab.RootDn },
    @{ Name = $Lab.UsersOuName; Parent = $Lab.RootDn; Dn = $Lab.UsersDn },
    @{ Name = $Lab.ServiceAccountsOuName; Parent = $Lab.RootDn; Dn = $Lab.ServiceAccountsDn },
    @{ Name = $Lab.GroupsOuName; Parent = $Lab.RootDn; Dn = $Lab.GroupsDn },
    @{ Name = $Lab.ServersOuName; Parent = $Lab.RootDn; Dn = $Lab.ServersDn }
)
foreach ($definition in $ouDefinitions) {
    $existing = Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$($definition.Dn))" -SearchBase $Lab.BaseDn -Properties Description -ErrorAction Stop
    if ($existing) {
        if ($existing.Description -cne $Lab.Marker) { throw ('OU already exists without the lab marker: {0}' -f $definition.Dn) }
        Write-LabStep SKIP ('OU exists: {0}' -f $definition.Dn)
    } else {
        New-ADOrganizationalUnit -Name $definition.Name -Path $definition.Parent -Description $Lab.Marker -ProtectedFromAccidentalDeletion $true -ErrorAction Stop | Out-Null
        Write-LabStep OK ('Created OU: {0}' -f $definition.Dn)
    }
}
