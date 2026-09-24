# FOR ISOLATED TEST ACTIVE DIRECTORY ONLY. DO NOT RUN AGAINST PRODUCTION DOMAIN.
# Shared read-only checks for the DC certificate in Local Computer\Personal.
function Test-LabCertificateHostname {
    param([Parameter(Mandatory)]$Certificate, [Parameter(Mandatory)][string]$DnsName)
    $sanNames = @($Certificate.DnsNameList | ForEach-Object { $_.Unicode } | Where-Object { $_ })
    if ($sanNames.Count -gt 0) {
        return @($sanNames | Where-Object { $_ -ieq $DnsName }).Count -gt 0
    }
    $subjectDns = $Certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
    return $subjectDns -ieq $DnsName
}

function Test-LabServerAuthEku {
    param([Parameter(Mandatory)]$Certificate)
    $eku = @($Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($eku.Count -ne 1) { return $false }
    $typedEku = New-Object Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($eku[0], $eku[0].Critical)
    return @($typedEku.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.1' }).Count -gt 0
}

function Test-LabCertificateChain {
    param([Parameter(Mandatory)]$Certificate)
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(10)
        return $chain.Build($Certificate)
    } finally {
        $chain.Dispose()
    }
}

function Get-LabLdapsCertificateReport {
    param([Parameter(Mandatory)][string]$DnsName)
    $now = Get-Date
    foreach ($certificate in @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop)) {
        $hostname = Test-LabCertificateHostname -Certificate $certificate -DnsName $DnsName
        $eku = Test-LabServerAuthEku -Certificate $certificate
        if (-not $hostname -and -not $eku) { continue }
        $validDates = $certificate.NotBefore -le $now -and $certificate.NotAfter -gt $now
        $chain = if ($validDates) { Test-LabCertificateChain -Certificate $certificate } else { $false }
        [pscustomobject]@{
            Certificate = $certificate
            Thumbprint = $certificate.Thumbprint
            Hostname = $hostname
            ServerAuthEku = $eku
            PrivateKey = $certificate.HasPrivateKey
            ValidDates = $validDates
            Chain = $chain
        }
    }
}
