<#
.SYNOPSIS
  Exports the CA certificates your network uses to re-sign HTTPS traffic (for example Cisco Secure
  Access / Umbrella, Zscaler) to certs\network-root-ca.pem, so the container can trust them.

.DESCRIPTION
  Opens a TLS connection to the host (default api.openai.com) and reads the certificate chain that
  Windows builds for it. It writes the chain's root CA and any long-lived intermediate CAs as PEM -
  never the site's own certificate, and not short-lived intermediates (which rotate and are sent by
  the network during each connection anyway). If Windows does not supply the issuing CAs, it looks
  in the Windows certificate stores by name. It changes no system settings and sends no data beyond
  a normal TLS handshake.

  Confirm with your IT/security team that the exported certificates are your organisation's
  expected inspection CAs before trusting them.

.PARAMETER SkipIfPublic
  Exit without writing anything if the site's certificate looks publicly issued (traffic not inspected).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\export-network-root-ca.ps1
#>
param(
  [string]$HostName = "api.openai.com",
  [int]$Port = 443,
  [string]$OutFile = (Join-Path $PSScriptRoot "..\certs\network-root-ca.pem"),
  [int]$MinIntermediateDays = 90,
  [switch]$SkipIfPublic
)

$ErrorActionPreference = "Stop"
$PublicIssuers = "DigiCert|GlobalSign|Google Trust|Let's Encrypt|ISRG|Sectigo|Baltimore|Amazon|Microsoft|Entrust|GoDaddy|Starfield|Comodo|USERTrust|Cloudflare"

function Test-IsCA($cert) {
  foreach ($ext in $cert.Extensions) {
    if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
      return $ext.CertificateAuthority
    }
  }
  return ($cert.Subject -eq $cert.Issuer)
}

function Find-InStores($subject) {
  foreach ($loc in "CurrentUser", "LocalMachine") {
    foreach ($store in "Root", "CA", "AuthRoot") {
      $hit = Get-ChildItem -Path "Cert:\$loc\$store" -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
      if ($hit) { return $hit }
    }
  }
  return $null
}

# 1. Connect and capture the chain Windows builds during the handshake. This includes intermediate
#    certificates the server (or inspection proxy) sends, which are not stored in Windows.
$script:handshakeChain = @()
$callback = [System.Net.Security.RemoteCertificateValidationCallback]{
  param($sender, $certificate, $chain, $sslPolicyErrors)
  if ($chain) {
    foreach ($el in $chain.ChainElements) {
      $script:handshakeChain += (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($el.Certificate))
    }
  }
  # Accept only so the chain can be read; nothing is sent over this connection.
  return $true
}
$client = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
try {
  $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, $callback)
  $ssl.AuthenticateAsClient($HostName)
  $leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
} finally {
  $client.Dispose()
}

Write-Host "Site certificate presented for ${HostName}:" $leaf.Subject
Write-Host "  issued by:" $leaf.Issuer

if ($SkipIfPublic -and $leaf.Issuer -match $PublicIssuers) {
  Write-Host "This looks like a publicly issued certificate, so your network is not inspecting this traffic."
  Write-Host "No extra CA certificates are needed. Nothing was written."
  exit 0
}

# 2. Collect CA certificates from the handshake chain, then from a fresh local chain build.
$script:cas = @()
function Add-CA($c) {
  if ($c.Thumbprint -ne $leaf.Thumbprint -and (Test-IsCA $c) -and -not ($script:cas | Where-Object { $_.Thumbprint -eq $c.Thumbprint })) {
    $script:cas += $c
  }
}
foreach ($c in $script:handshakeChain) { Add-CA $c }
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
[void]$chain.Build($leaf)
foreach ($el in $chain.ChainElements) { Add-CA $el.Certificate }

# 3. Fill any gaps by walking issuers through the Windows certificate stores.
$current = if ($script:cas.Count -gt 0) { $script:cas[-1] } else { $leaf }
for ($i = 0; $i -lt 5 -and $current.Subject -ne $current.Issuer; $i++) {
  $issuer = Find-InStores $current.Issuer
  if (-not $issuer) { break }
  Add-CA $issuer
  $current = $issuer
}

# 4. Last resort: any root in the Windows stores whose name matches the inspection product
#    named in the issuer (for example "Cisco Secure Access" or "Cisco Umbrella").
if (-not ($script:cas | Where-Object { $_.Subject -eq $_.Issuer })) {
  $hint = if ($leaf.Issuer -match "CN=([^,]+?)\s+(Secondary\s+|Primary\s+)?Sub\s*CA") { $Matches[1] } else { $null }
  if ($hint) {
    Write-Host "Searching Windows certificate stores for roots matching '$hint'..."
    foreach ($loc in "CurrentUser", "LocalMachine") {
      foreach ($store in "Root", "AuthRoot") {
        Get-ChildItem -Path "Cert:\$loc\$store" -ErrorAction SilentlyContinue |
          Where-Object { $_.Subject -eq $_.Issuer -and $_.Subject -like "*$hint*" } |
          ForEach-Object { Add-CA $_ }
      }
    }
  }
}

if ($script:cas.Count -eq 0) {
  Write-Host ""
  Write-Host "Could not find the issuing CA certificates for this site in Windows." -ForegroundColor Yellow
  Write-Host "Ask IT for your network's inspection root CA (PEM) and save it in the certs folder." -ForegroundColor Yellow
  exit 1
}

# 5. Keep roots and long-lived intermediates. Short-lived intermediates rotate and are sent by the
#    network on every connection; storing them would cause failures once they expire.
$haveRoot = [bool]($script:cas | Where-Object { $_.Subject -eq $_.Issuer })
$cutoff = (Get-Date).AddDays($MinIntermediateDays)
$keep = @()
Write-Host ""
foreach ($c in $script:cas) {
  $isRoot = $c.Subject -eq $c.Issuer
  $kind = if ($isRoot) { "root" } else { "intermediate" }
  $shortLived = (-not $isRoot) -and $haveRoot -and ($c.NotAfter -lt $cutoff)
  $sha = $c.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)
  if ($shortLived) {
    Write-Host " - skipped [$kind, expires $($c.NotAfter.ToString('yyyy-MM-dd'))]" $c.Subject -ForegroundColor DarkGray
  } else {
    $keep += $c
    Write-Host " - [$kind]" $c.Subject
    Write-Host "   SHA-256:" $sha " expires:" $c.NotAfter.ToString("yyyy-MM-dd")
  }
}
if (-not $haveRoot) {
  Write-Host "Note: no self-signed root was found; the intermediates alone are usually sufficient." -ForegroundColor Yellow
}

$pem = ""
foreach ($c in $keep) {
  $b64 = [Convert]::ToBase64String($c.RawData, [Base64FormattingOptions]::InsertLineBreaks)
  $pem += "# Subject: $($c.Subject)`n# Issuer:  $($c.Issuer)`n-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----`n`n"
}
$full = [System.IO.Path]::GetFullPath($OutFile)
New-Item -ItemType Directory -Force -Path (Split-Path $full) | Out-Null
[System.IO.File]::WriteAllText($full, $pem)
Write-Host ""
Write-Host "CA certificates written to $full (confirm these with IT)."
