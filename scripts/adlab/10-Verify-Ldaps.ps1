# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param([Management.Automation.PSCredential]$Credential)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
. (Join-Path $PSScriptRoot 'LdapsCertificateChecks.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
$null = Assert-LabDomain
$rows = New-Object 'System.Collections.Generic.List[object]'
function Add-Result {
    param([string]$Check, [bool]$Passed, [string]$Detail = '')
    $rows.Add([pscustomobject]@{ Check = $Check; Status = if ($Passed) { 'OK' } else { 'FAIL' }; Detail = $Detail })
}
$addresses = @(Resolve-DnsName -Name $Lab.Server -ErrorAction SilentlyContinue | Where-Object { $_.Type -in @('A', 'AAAA') })
Add-Result 'DNS resolution' ($addresses.Count -gt 0)
$tcp = $false
if ($addresses.Count -gt 0) { $tcp = [bool](Test-NetConnection -ComputerName $Lab.Server -Port 636 -InformationLevel Quiet -WarningAction SilentlyContinue) }
Add-Result 'TCP 636' $tcp

$reports = @(Get-LabLdapsCertificateReport -DnsName $Lab.Server)
$selected = $reports | Where-Object { $_.Hostname } | Select-Object -First 1
if (-not $selected) { $selected = $reports | Select-Object -First 1 }
if ($reports.Count -gt 1) { Write-Warning 'Multiple potential LDAPS certificates are present. AD DS may select a different certificate; inspect NTDS and Local Computer stores.' }
Add-Result 'DC certificate found' ([bool]$selected)
Add-Result 'Private key' ([bool]($selected -and $selected.PrivateKey))
Add-Result 'Server Authentication EKU' ([bool]($selected -and $selected.ServerAuthEku))
Add-Result 'Hostname/SAN' ([bool]($selected -and $selected.Hostname))
Add-Result 'Certificate dates' ([bool]($selected -and $selected.ValidDates))
Add-Result 'Chain' ([bool]($selected -and $selected.Chain))

if ($Credential) {
    $bindPassed = $false
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols
        $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Lab.Server, 636)
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier, $Credential.GetNetworkCredential(), [System.DirectoryServices.Protocols.AuthType]::Negotiate)
        try {
            $connection.Timeout = [TimeSpan]::FromSeconds(10)
            $connection.SessionOptions.ProtocolVersion = 3
            $connection.SessionOptions.SecureSocketLayer = $true
            $connection.Bind()
            $request = New-Object System.DirectoryServices.Protocols.SearchRequest($Lab.BaseDn, '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, @('objectClass'))
            $response = [System.DirectoryServices.Protocols.SearchResponse]$connection.SendRequest($request)
            $bindPassed = $response.Entries.Count -gt 0
        } finally { $connection.Dispose() }
    } catch {
        Write-Warning ('LDAPS bind/Base DN check failed ({0}).' -f $_.Exception.GetType().Name)
    }
    Add-Result 'LDAPS bind + Base DN' $bindPassed
} else {
    $rows.Add([pscustomobject]@{ Check = 'LDAPS bind + Base DN'; Status = 'NOT TESTED'; Detail = 'Pass -Credential to test with the scanner account.' })
}

$rows | Format-Table -Property Check, Status, Detail -AutoSize
if (@($rows | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { throw 'LDAPS verification failed. TCP success alone does not prove valid TLS.' }
Write-LabStep OK 'DC-side LDAPS checks completed. Test again from the application host.'
