# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param([switch]$ConfirmLabChanges)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
if (-not $ConfirmLabChanges) { throw 'Pass -ConfirmLabChanges after verifying this is the isolated adlab.test VM.' }
Assert-LabAdministrator
$domain = Assert-LabDomain
Assert-LabStructure

function Require-User {
    param([string]$Name, [switch]$Service)
    $parent = if ($Service) { $Lab.ServiceAccountsDn } else { $Lab.UsersDn }
    $user = Get-LabUser -SamAccountName $Name -ExpectedParentDn $parent
    if (-not $user) { throw "Missing lab user $Name. Run 03-Create-LabAccounts.ps1 first." }
    return $user
}

function Ensure-LabSpn {
    param([string]$AccountName, [string]$Spn)
    $user = Require-User -Name $AccountName -Service
    $user = Get-ADUser -Identity $user -Properties ServicePrincipalName
    if (@($user.ServicePrincipalName | Where-Object { $_ -ieq $Spn }).Count -gt 0) {
        Write-LabStep SKIP ("SPN already on $AccountName`: $Spn")
        return
    }
    # The lab forest has exactly one domain. Query its AD objects without parsing localized setspn output.
    $spnOwners = @(Get-ADObject -LDAPFilter "(servicePrincipalName=$Spn)" -SearchBase $Lab.BaseDn -ErrorAction Stop)
    if ($spnOwners.Count -gt 0) { throw ("SPN already exists; refusing duplicate: {0}" -f $Spn) }
    # setspn -S performs an additional duplicate check during the write.
    $add = & setspn.exe -S $Spn ("{0}\{1}" -f $Lab.NetbiosName, $AccountName) 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("Could not add SPN {0}: {1}" -f $Spn, ($add -join ' ')) }
    Write-LabStep OK ("Added unique SPN $Spn to $AccountName")
}

function Ensure-DelegationTarget {
    param([string]$AccountName, [string]$TargetSpn)
    $user = Require-User -Name $AccountName -Service
    $current = Get-ADUser -Identity $user -Properties 'msDS-AllowedToDelegateTo'
    if (@($current.'msDS-AllowedToDelegateTo' | Where-Object { $_ -ieq $TargetSpn }).Count -gt 0) {
        Write-LabStep SKIP ("Delegation target exists on $AccountName`: $TargetSpn")
    } else {
        Set-ADUser -Identity $user -Add @{ 'msDS-AllowedToDelegateTo' = $TargetSpn }
        Write-LabStep OK ("Added delegation target to $AccountName`: $TargetSpn")
    }
}

function Ensure-LockoutPolicy {
    $pso = Get-ADFineGrainedPasswordPolicy -Filter * -Properties Description -ErrorAction Stop |
        Where-Object Name -EQ $Lab.LockoutPsoName
    if (-not $pso) {
        New-ADFineGrainedPasswordPolicy -Name $Lab.LockoutPsoName -Description $Lab.Marker -Precedence 1 -ComplexityEnabled $true -MinPasswordLength 8 -PasswordHistoryCount 0 -MinPasswordAge '00:00:00' -MaxPasswordAge '90.00:00:00' -LockoutThreshold 3 -LockoutDuration '00:30:00' -LockoutObservationWindow '00:10:00' -ErrorAction Stop | Out-Null
        Write-LabStep OK ('Created lab-only PSO: {0}' -f $Lab.LockoutPsoName)
    } else {
        if ($pso.Description -cne $Lab.Marker) { throw 'Existing PSO lacks the lab marker. Refusing to change it.' }
        if ($pso.LockoutThreshold -ne 3 -or $pso.LockoutDuration -ne [TimeSpan]::FromMinutes(30) -or $pso.LockoutObservationWindow -ne [TimeSpan]::FromMinutes(10)) {
            throw 'Existing lab PSO differs from expected settings. Inspect it manually; script will not overwrite an unknown policy.'
        }
        Write-LabStep SKIP ('PSO exists: {0}' -f $Lab.LockoutPsoName)
    }
    $lockedUser = Require-User -Name 'lab_locked_user'
    $resultant = Get-ADUserResultantPasswordPolicy -Identity $lockedUser
    if (-not $resultant -or $resultant.Name -ine $Lab.LockoutPsoName) {
        Add-ADFineGrainedPasswordPolicySubject -Identity $Lab.LockoutPsoName -Subjects $lockedUser -ErrorAction Stop
    }
    $resultant = Get-ADUserResultantPasswordPolicy -Identity $lockedUser
    if (-not $resultant -or $resultant.Name -ine $Lab.LockoutPsoName) { throw 'Lab lockout PSO is not effective for lab_locked_user.' }
    Write-LabStep OK 'Lab-only lockout PSO is effective for lab_locked_user.'
}

function Ensure-ActualLockout {
    $user = Require-User -Name 'lab_locked_user'
    $state = Get-ADUser -Identity $user -Properties LockedOut, 'msDS-User-Account-Control-Computed'
    if ($state.LockedOut -and (($state.'msDS-User-Account-Control-Computed' -band 0x10) -ne 0)) {
        Write-LabStep SKIP 'lab_locked_user is already effectively locked.'
        return
    }
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Lab.Server, 389)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $wrongPassword = [Guid]::NewGuid().ToString('N')
        $credential = New-Object System.Net.NetworkCredential('lab_locked_user', $wrongPassword, $Lab.NetbiosName)
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier, $credential, [System.DirectoryServices.Protocols.AuthType]::Negotiate)
        try {
            $connection.Timeout = [TimeSpan]::FromSeconds(10)
            $connection.SessionOptions.ProtocolVersion = 3
            try {
                $connection.Bind()
                throw 'Unexpected successful authentication for lab_locked_user; aborting lockout scenario.'
            } catch [System.DirectoryServices.Protocols.LdapException] {
                Write-LabStep OK ("Deliberate failed authentication {0}/3" -f $attempt)
            }
        } finally {
            $connection.Dispose()
        }
        Start-Sleep -Seconds 1
        $state = Get-ADUser -Identity $user -Properties LockedOut, 'msDS-User-Account-Control-Computed'
        if ($state.LockedOut -and (($state.'msDS-User-Account-Control-Computed' -band 0x10) -ne 0)) {
            Write-LabStep OK 'lab_locked_user is effectively locked (LockedOut and computed UAC LOCKOUT).'
            return
        }
    }
    throw 'FAILED TO PREPARE LOCKED ACCOUNT SCENARIO: effective lockout was not observed.'
}

function Ensure-LabGmsa {
    $controllers = @(Get-ADDomainController -Filter * -Server $Lab.Server)
    if ($controllers.Count -ne 1) { throw 'gMSA fast KDS setup is permitted only in the single-DC lab.' }
    if ([string]$domain.DomainMode -notin @('Windows2012Domain', 'Windows2012R2Domain', 'Windows2016Domain', 'Windows2025Domain')) {
        throw 'gMSA requires Windows Server 2012 domain functional level or later.'
    }
    Import-Module Kds -ErrorAction Stop
    $keys = @(Get-KdsRootKey)
    if ($keys.Count -eq 0) {
        # Microsoft documents the backdated key shortcut only for a single-DC test lab.
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop | Out-Null
        Write-LabStep OK 'Created KDS root key with single-DC test-lab effective time.'
    } else { Write-LabStep SKIP 'KDS root key already exists.' }
    $hostGroup = Get-LabGroup -Name 'DemoGmsaHosts'
    if (-not $hostGroup) { throw 'Missing DemoGmsaHosts group.' }
    $dcComputer = Get-ADComputer -Identity $Lab.DcName -ErrorAction Stop
    Add-LabGroupMember -Group $hostGroup -Member $dcComputer
    $existing = Get-ADServiceAccount -LDAPFilter ("(sAMAccountName={0}$)" -f $Lab.GmsaName) -SearchBase $Lab.BaseDn -Properties DistinguishedName -ErrorAction Stop
    if ($existing) {
        $expected = 'CN={0},{1}' -f $Lab.GmsaName, $Lab.ServiceAccountsDn
        if ($existing.DistinguishedName -ine $expected) { throw 'gMSA exists outside the expected lab OU.' }
        Write-LabStep SKIP ('gMSA exists: {0}' -f $Lab.GmsaName)
    } else {
        New-ADServiceAccount -Name $Lab.GmsaName -DNSHostName ("{0}.{1}" -f $Lab.GmsaName, $Lab.DomainName) -Path $Lab.ServiceAccountsDn -PrincipalsAllowedToRetrieveManagedPassword $hostGroup -ErrorAction Stop | Out-Null
        Write-LabStep OK ('Created gMSA: {0}' -f $Lab.GmsaName)
    }
}

# Account and service scenarios.
$expired = Require-User -Name 'lab_expired_user'
Set-ADAccountExpiration -Identity $expired -DateTime ((Get-Date).AddDays(-1)) -ErrorAction Stop
Write-LabStep UPDATE 'lab_expired_user expires yesterday.'
foreach ($name in @('lab_pne_user', 'svc_sql')) {
    $user = Require-User -Name $name -Service:($name -eq 'svc_sql')
    Set-ADAccountControl -Identity $user -PasswordNeverExpires $true -ErrorAction Stop
    Write-LabStep UPDATE ("PasswordNeverExpires enabled: $name")
}
Ensure-LabSpn -AccountName 'svc_sql' -Spn ("MSSQLSvc/sql01.{0}:1433" -f $Lab.DomainName)
Ensure-LabSpn -AccountName 'svc_unconstrained' -Spn ("HTTP/unconstrained.{0}" -f $Lab.DomainName)
Ensure-LabSpn -AccountName 'svc_constrained' -Spn ("HTTP/constrained.{0}" -f $Lab.DomainName)
Ensure-LabSpn -AccountName 'svc_protocol_trans' -Spn ("HTTP/protocol.{0}" -f $Lab.DomainName)

# Direct and nested group edges. Built-in groups remain outside the lab OU by AD design.
$backup = Get-ADGroup -Identity 'S-1-5-32-551'
$serverOperators = Get-ADGroup -Identity 'S-1-5-32-549'
$domainAdmins = Get-ADGroup -Identity ('{0}-512' -f $domain.DomainSID.Value)
$helpDesk = Get-LabGroup -Name 'DemoHelpDesk'
$itAdmins = Get-LabGroup -Name 'DemoITAdmins'
if (-not $helpDesk -or -not $itAdmins) { throw 'Missing lab groups. Run 03 first.' }
Add-LabGroupMember -Group $backup -Member (Require-User -Name 'lab_direct_admin')
Add-LabGroupMember -Group $helpDesk -Member (Require-User -Name 'lab_nested_admin')
Add-LabGroupMember -Group $itAdmins -Member $helpDesk
Add-LabGroupMember -Group $domainAdmins -Member $itAdmins
Add-LabGroupMember -Group $backup -Member (Require-User -Name 'lab_multi_admin')
Add-LabGroupMember -Group $serverOperators -Member (Require-User -Name 'lab_multi_admin')

# Delegation mechanisms use the same LDAP attributes consumed by the app.
$unconstrained = Require-User -Name 'svc_unconstrained' -Service
Set-ADAccountControl -Identity $unconstrained -TrustedForDelegation $true -ErrorAction Stop
Write-LabStep UPDATE 'Enabled TRUSTED_FOR_DELEGATION on svc_unconstrained.'
$targetSpn = 'HTTP/app01.{0}' -f $Lab.DomainName
Ensure-DelegationTarget -AccountName 'svc_constrained' -TargetSpn $targetSpn
Ensure-DelegationTarget -AccountName 'svc_protocol_trans' -TargetSpn $targetSpn
Set-ADAccountControl -Identity (Require-User -Name 'svc_protocol_trans' -Service) -TrustedToAuthForDelegation $true -ErrorAction Stop
Write-LabStep UPDATE 'Enabled TRUSTED_TO_AUTH_FOR_DELEGATION on svc_protocol_trans.'
$rbcdSource = Require-User -Name 'svc_rbcd_source' -Service
$rbcdTarget = Require-User -Name 'svc_rbcd_target' -Service
Set-ADUser -Identity $rbcdTarget -PrincipalsAllowedToDelegateToAccount $rbcdSource -ErrorAction Stop
Write-LabStep UPDATE 'Configured RBCD on svc_rbcd_target for svc_rbcd_source.'

Ensure-LabGmsa
Ensure-LockoutPolicy
Ensure-ActualLockout
Write-LabStep OK 'Lab risk scenarios configured. Run 06-Verify-Lab.ps1.'
