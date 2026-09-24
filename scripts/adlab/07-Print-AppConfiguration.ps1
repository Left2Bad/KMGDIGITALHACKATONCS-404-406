# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
[CmdletBinding()]
param([switch]$Ldaps)
. (Join-Path $PSScriptRoot 'LabConfig.ps1')
Write-Warning 'FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.'
Write-Host ('Server = {0}' -f $Lab.Server)
Write-Host ('Port = {0}' -f $(if ($Ldaps) { 636 } else { 389 }))
Write-Host ('UseSsl = {0}' -f $(if ($Ldaps) { 'true' } else { 'false' }))
Write-Host ('BaseDn = {0}' -f $Lab.BaseDn)
Write-Host ('Username = {0}\{1}' -f $Lab.NetbiosName, $Lab.ScannerAccount)
Write-Host 'Password = <set through .NET User Secrets; never store in appsettings.json>'
