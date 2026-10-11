# Tworzy GitHub Release v2.0.0 z binarka tznsecvirus.exe
# Uzycie (PowerShell):
#   $env:GITHUB_TOKEN = "ghp_..."      # token z scopes: contents:write
#   .\tools\make_release.ps1
#
# Alternatywa bez skryptu: GitHub -> Releases -> Draft a new release
#   tag v2.0.0, zalacz plik tznsecvirus.exe

param(
  [string]$Repo     = "tznsec/tznsecvirus",
  [string]$Tag      = "v2.0.0",
  [string]$ExePath  = "tznsecvirus.exe",
  [string]$AssetName= "TZNSECVIRUS.exe"
)

$ErrorActionPreference = "Stop"

if (-not $env:GITHUB_TOKEN) {
  Write-Host "Brak $env:GITHUB_TOKEN - ustaw token GitHub z uprawnieniami contents:write" -ForegroundColor Red
  exit 1
}
if (-not (Test-Path -LiteralPath $ExePath)) {
  Write-Host "Nie znaleziono $ExePath" -ForegroundColor Red
  exit 1
}

$headers = @{
  Authorization = "Bearer $env:GITHUB_TOKEN"
  Accept        = "application/vnd.github+json"
  "User-Agent"  = "tznsec-release-script"
}

# --- hash ---
$hash = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash.ToLower()
Write-Host "SHA256: $hash"

# --- 1. Release ---
$body = @{
  tag_name         = $Tag
  target_commitish = "main"
  name             = "TZNSECVIRUS 2.0.0"
  body             = "Skaner bezpieczenstwa komputera z analiza AI (Rust + WebView)."
  draft            = $false
  prerelease       = $false
} | ConvertTo-Json

try {
  $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases" `
        -Method Post -Headers $headers -Body $body -ContentType "application/json"
  Write-Host "Release utworzony: $($rel.html_url)" -ForegroundColor Green
} catch {
  if ($_.Exception.Message -match "already_exists") {
    Write-Host "Release $Tag juz istnieje - pobieram go..." -ForegroundColor Yellow
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/tags/$Tag" -Headers $headers
  } else {
    Write-Host "Blad tworzenia release: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
  }
}

# --- 2. Asset ---
$uploadUrl = $rel.upload_url -replace '\{.*\}$',''
$assetPath = Join-Path $env:TEMP $AssetName
Copy-Item -LiteralPath $ExePath -Destination $assetPath -Force

$boundary = "----tznsec$([guid]::NewGuid().ToString('N'))"
$bytes = [System.IO.File]::ReadAllBytes($assetPath)
$header = "--$boundary`r`nContent-Disposition: form-data; name=`"asset`"; filename=`"$AssetName`"`r`nContent-Type: application/octet-stream`r`n`r`n"
$footer = "`r`n--$boundary--`r`n"

$ms = New-Object System.IO.MemoryStream
$enc = [System.Text.Encoding]::ASCII
$ms.Write($enc.GetBytes($header), 0, $header.Length)
$ms.Write($bytes, 0, $bytes.Length)
$ms.Write($enc.GetBytes($footer), 0, $footer.Length)
$bodyBytes = $ms.ToArray()
$ms.Dispose()

try {
  Invoke-RestMethod -Uri "$uploadUrl?name=$AssetName" -Method Post `
    -Headers @{ Authorization = "Bearer $env:GITHUB_TOKEN"; "User-Agent" = "tznsec" } `
    -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyBytes | Out-Null
  Write-Host "Asset przeslany: $AssetName" -ForegroundColor Green
} catch {
  Write-Host "Blad wysylania assetu: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}

$url = "https://github.com/$Repo/releases/download/$Tag/$AssetName"
Write-Host ""
Write-Host "Gotowe. Asset URL:" -ForegroundColor Cyan
Write-Host "  $url"

# --- 3. Podpowiedz aktualizacje hasha w manifeście ---
$manifest = Join-Path (Split-Path $PSScriptRoot -Parent) "winget\TZNSECVIRUS.installer.yaml"
if (Test-Path -LiteralPath $manifest) {
  $content = Get-Content -LiteralPath $manifest -Raw
  $updated = $content -replace '(?i)(InstallerSha256:\s*)\w+', "`${1}$($hash.ToUpper())"
  $updated = $updated -replace '(?i)(FileSha256:\s*)\w+', "`${1}$($hash.ToUpper())"
  Set-Content -LiteralPath $manifest -Value $updated -NoNewline
  Write-Host ""
  Write-Host "Zaktualizowano SHA256 w: winget\TZNSECVIRUS.installer.yaml" -ForegroundColor Green
}