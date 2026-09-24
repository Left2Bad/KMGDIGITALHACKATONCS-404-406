# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
$Lab = @{
    DomainName = 'adlab.test'
    NetbiosName = 'ADLAB'
    DcName = 'DC01'
    RootOuName = 'HackathonLab'
    UsersOuName = 'Users'
    ServiceAccountsOuName = 'ServiceAccounts'
    GroupsOuName = 'Groups'
    ServersOuName = 'Servers'
    ScannerAccount = 'svc_ira_scanner'
    LockoutPsoName = 'HackathonLab-LockoutPSO'
    GmsaName = 'gmsa_demo'
    Marker = 'IdentityRiskAnalyzer P1-16 isolated adlab.test lab'
}

$Lab.BaseDn = (($Lab.DomainName -split '\.' | ForEach-Object { 'DC=' + $_ }) -join ',')
$Lab.RootDn = 'OU={0},{1}' -f $Lab.RootOuName, $Lab.BaseDn
$Lab.UsersDn = 'OU={0},{1}' -f $Lab.UsersOuName, $Lab.RootDn
$Lab.ServiceAccountsDn = 'OU={0},{1}' -f $Lab.ServiceAccountsOuName, $Lab.RootDn
$Lab.GroupsDn = 'OU={0},{1}' -f $Lab.GroupsOuName, $Lab.RootDn
$Lab.ServersDn = 'OU={0},{1}' -f $Lab.ServersOuName, $Lab.RootDn
$Lab.Server = ('{0}.{1}' -f $Lab.DcName, $Lab.DomainName).ToLowerInvariant()

function Write-LabStep {
    param([string]$State, [string]$Message)
    Write-Host ('[{0}] {1}' -f $State, $Message)
}

function Assert-LabAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script in an elevated Windows PowerShell session.'
    }
}

function Assert-LabDomain {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    if ($domain.DNSRoot -ine $Lab.DomainName -or $domain.NetBIOSName -ine $Lab.NetbiosName) {
        throw ('Refusing to modify domain {0}. Expected exactly {1} ({2}).' -f $domain.DNSRoot, $Lab.DomainName, $Lab.NetbiosName)
    }
    if ($env:COMPUTERNAME -ine $Lab.DcName) {
        throw ('Run locally on {0}; current computer is {1}.' -f $Lab.DcName, $env:COMPUTERNAME)
    }
    $controllers = @(Get-ADDomainController -Filter * -Server $Lab.Server -ErrorAction Stop)
    if ($controllers.Count -ne 1 -or $controllers[0].HostName -ine $Lab.Server) {
        throw 'This lab requires exactly one DC named DC01. Refusing to modify a different topology.'
    }
    return $domain
}

function Get-LabUser {
    param([Parameter(Mandatory)][string]$SamAccountName, [string]$ExpectedParentDn = $Lab.UsersDn)
    $foundUsers = @(Get-ADUser -LDAPFilter "(sAMAccountName=$SamAccountName)" -SearchBase $Lab.BaseDn -Properties DistinguishedName -ErrorAction Stop)
    if ($foundUsers.Count -gt 1) { throw "Ambiguous lab user: $SamAccountName" }
    if ($foundUsers.Count -eq 0) { return $null }
    $expectedDn = 'CN={0},{1}' -f $SamAccountName, $ExpectedParentDn
    if ($foundUsers[0].DistinguishedName -ine $expectedDn) {
        throw ("Refusing to change {0}: object exists outside expected lab location {1}." -f $SamAccountName, $expectedDn)
    }
    return $foundUsers[0]
}

function Get-LabGroup {
    param([Parameter(Mandatory)][string]$Name)
    $foundGroups = @(Get-ADGroup -LDAPFilter "(sAMAccountName=$Name)" -SearchBase $Lab.BaseDn -Properties DistinguishedName -ErrorAction Stop)
    if ($foundGroups.Count -gt 1) { throw "Ambiguous lab group: $Name" }
    if ($foundGroups.Count -eq 0) { return $null }
    $expectedDn = 'CN={0},{1}' -f $Name, $Lab.GroupsDn
    if ($foundGroups[0].DistinguishedName -ine $expectedDn) {
        throw ("Refusing to change {0}: group exists outside {1}." -f $Name, $expectedDn)
    }
    return $foundGroups[0]
}

function Assert-LabStructure {
    $ou = Get-ADOrganizationalUnit -Identity $Lab.RootDn -Properties Description -ErrorAction Stop
    if ($ou.DistinguishedName -ine $Lab.RootDn -or $ou.Description -cne $Lab.Marker) {
        throw 'Lab OU is missing or does not carry the expected P1-16 marker.'
    }
}

function Test-DirectGroupMember {
    param([Parameter(Mandatory)]$Group, [Parameter(Mandatory)]$Member)
    $groupObject = Get-ADGroup -Identity $Group -Properties member -ErrorAction Stop
    return @($groupObject.member | Where-Object { $_ -ieq $Member.DistinguishedName }).Count -gt 0
}

function Add-LabGroupMember {
    param([Parameter(Mandatory)]$Group, [Parameter(Mandatory)]$Member)
    if (Test-DirectGroupMember -Group $Group -Member $Member) {
        Write-LabStep SKIP ("Membership exists: {0} -> {1}" -f $Member.Name, $Group.Name)
    } else {
        Add-ADGroupMember -Identity $Group -Members $Member -ErrorAction Stop
        Write-LabStep OK ("Added membership: {0} -> {1}" -f $Member.Name, $Group.Name)
    }
}

function Test-LabScannerUnprivileged {
    param([Parameter(Mandatory)]$Scanner, [Parameter(Mandatory)]$Domain)
    $adminSids = @(
        'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551',
        ('{0}-512' -f $Domain.DomainSID.Value), ('{0}-518' -f $Domain.DomainSID.Value), ('{0}-519' -f $Domain.DomainSID.Value)
    )
    foreach ($sid in $adminSids) {
        $group = Get-ADGroup -Identity $sid -ErrorAction SilentlyContinue
        if (-not $group) { continue }
        $members = @(Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop)
        if (@($members | Where-Object { $_.DistinguishedName -ieq $Scanner.DistinguishedName }).Count -gt 0) { return $false }
    }
    $dnsAdmins = Get-ADGroup -Identity 'DNSAdmins' -ErrorAction SilentlyContinue
    if ($dnsAdmins) {
        $members = @(Get-ADGroupMember -Identity $dnsAdmins -Recursive -ErrorAction Stop)
        if (@($members | Where-Object { $_.DistinguishedName -ieq $Scanner.DistinguishedName }).Count -gt 0) { return $false }
    }
    return $true
}
