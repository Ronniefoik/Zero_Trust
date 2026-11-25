$ErrorActionPreference = 'Stop'

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw 'Nie znaleziono Pythona. Zainstaluj Python 3.10+ i zaznacz opcję dodania do PATH.'
}

$pythonVersion = & python -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ($LASTEXITCODE -ne 0) {
    throw 'Nie można uruchomić Pythona. Sprawdź instalację lub alias WindowsApps.'
}
$versionParts = $pythonVersion.Split('.') | ForEach-Object { [int]$_ }
if (($versionParts[0] -lt 3) -or (($versionParts[0] -eq 3) -and ($versionParts[1] -lt 10))) {
    throw "Wymagany jest Python 3.10 lub nowszy; znaleziono $pythonVersion."
}

$secretBytes = New-Object byte[] 48
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($secretBytes)
$env:SESSION_SECRET = [Convert]::ToBase64String($secretBytes)
$rng.Dispose()
[Array]::Clear($secretBytes, 0, $secretBytes.Length)
$env:API_USERS_FILE = Join-Path $PSScriptRoot 'data\users.json'
$env:API_AUDIT_FILE = Join-Path $PSScriptRoot 'logs\audit.jsonl'
$env:TLS_CERT_FILE = Join-Path $PSScriptRoot 'tls\dev-cert.pem'
$env:TLS_KEY_FILE = Join-Path $PSScriptRoot 'tls\dev-key.pem'
$env:API_BIND_HOST = '127.0.0.1'
$env:API_PORT = '8443'
$env:API_ALLOWED_NETWORKS = '127.0.0.1/32,::1/128'
$env:AUTH_MODE = 'local'

if (-not (Test-Path -LiteralPath $env:TLS_CERT_FILE) -or -not (Test-Path -LiteralPath $env:TLS_KEY_FILE)) {
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw 'Do automatycznego utworzenia certyfikatu użyj PowerShell 7+ albo przygotuj tls/dev-cert.pem i tls/dev-key.pem poleceniem OpenSSL opisanym w README.'
    }
    & (Join-Path $PSScriptRoot 'generate_dev_certificate.ps1')
}
if ($LASTEXITCODE -ne 0) {
    throw 'Nie udało się utworzyć certyfikatu demonstracyjnego.'
}

if (-not (Test-Path -LiteralPath $env:API_USERS_FILE)) {
    & python (Join-Path $PSScriptRoot 'local_api.py') init-users --file $env:API_USERS_FILE
    if ($LASTEXITCODE -ne 0) {
        throw 'Nie udało się utworzyć kont demonstracyjnych.'
    }
}

Write-Output 'API będzie dostępne wyłącznie lokalnie przez HTTPS na https://localhost:8443.'
Write-Output 'W drugim oknie uruchom: python demo_client.py read (lub deny-ack / ack / logout).'
& python (Join-Path $PSScriptRoot 'local_api.py') serve
exit $LASTEXITCODE
