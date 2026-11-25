$ErrorActionPreference = 'Stop'

# Self-signed certificate for the local classroom demo only.
# For a remote/tunnel deployment, use certificates issued by the team's CA.
$targetDirectory = Join-Path $PSScriptRoot 'tls'
New-Item -ItemType Directory -Force -Path $targetDirectory | Out-Null
$certPath = Join-Path $targetDirectory 'dev-cert.pem'
$keyPath = Join-Path $targetDirectory 'dev-key.pem'

$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new('CN=localhost')
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    $subject,
    $rsa,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)
$san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$san.AddDnsName('localhost')
$san.AddIpAddress([System.Net.IPAddress]::Parse('127.0.0.1'))
$san.AddIpAddress([System.Net.IPAddress]::IPv6Loopback)
$request.CertificateExtensions.Add($san.Build())
$request.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false)
)
$request.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,
        $false
    )
)
$certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(30))

function Write-PemFile([string]$Path, [string]$Label, [byte[]]$Bytes) {
    $encoded = [Convert]::ToBase64String($Bytes)
    $lines = for ($offset = 0; $offset -lt $encoded.Length; $offset += 64) {
        $count = [Math]::Min(64, $encoded.Length - $offset)
        $encoded.Substring($offset, $count)
    }
    $pem = "-----BEGIN $Label-----`n$($lines -join "`n")`n-----END $Label-----`n"
    [System.IO.File]::WriteAllText($Path, $pem, [System.Text.Encoding]::ASCII)
}

Write-PemFile -Path $certPath -Label 'CERTIFICATE' -Bytes $certificate.RawData
Write-PemFile -Path $keyPath -Label 'PRIVATE KEY' -Bytes $rsa.ExportPkcs8PrivateKey()
$rsa.Dispose()
$certificate.Dispose()
Write-Output "Zapisano lokalny certyfikat demo: $certPath"
