$ErrorActionPreference = "Stop"

# Token ustaw w srodowisku, NIGDY w kodzie (GitHub blokuje push z sekretem):
#   $env:GITHUB_TOKEN = "ghp_..."
if (-not $env:GITHUB_TOKEN) {
  Write-Host "Brak $env:GITHUB_TOKEN - ustaw token z uprawnieniami (contents:write, pull_requests:write)" -ForegroundColor Red
  exit 1
}
$token = $env:GITHUB_TOKEN

$h = @{ Authorization = "Bearer $token"; Accept = "application/vnd.github+json"; "User-Agent" = "tznsec" }
$ForkRepo  = "tznsec/winget-pkgs"
$UpRepo    = "microsoft/winget-pkgs"
$ID        = "tznsecvirus.TZNSECVIRUS"   # PackageIdentifier - musi byc prefiksem nazw plikow
$Version   = "2.0.0"
$Partition = "tznsecvirus".Substring(0,1).ToLower()
$Dir       = "manifests/$Partition/$ID/$Version"
$Branch    = "tznsecvirus-tznsecvirus-2.0.0"   # istniejaca galeaz z PR
$LocalDir  = Join-Path (Split-Path $PSScriptRoot -Parent) "winget"
# pusty blob - wymagany przez API przy usuwaniu plikow z drzewa
$EMPTY_BLOB = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"

# Pliki MUSZA byc nazwane jak PackageIdentifier (walidacja winget tego wymaga)
$files = @("$ID.yaml", "$ID.installer.yaml", "$ID.locale.pl-PL.yaml")

function Api($url, $method, $obj) {
  $json = $obj | ConvertTo-Json -Depth 10 -Compress
  try {
    return Invoke-RestMethod -Uri $url -Method $method -Headers $h -Body $json -ContentType "application/json" -TimeoutSec 120
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
      Write-Host ("HTTP {0}: {1}" -f [int]$resp.StatusCode, $sr.ReadToEnd())
    } else { Write-Host ("ERR: " + $_.Exception.Message) }
    throw
  }
}

# --- baza: aktualny head galezi (jesli istnieje) albo master ---
$headSha = $null
try {
  $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$ForkRepo/git/ref/heads/$Branch" -Headers $h
  $headSha = $r.object.sha
  Write-Host "galez istnieje: $Branch @ $($headSha.Substring(0,8))"
} catch {
  $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$ForkRepo/git/ref/heads/master" -Headers $h
  $headSha = $r.object.sha
  Write-Host "tworze galeaz $Branch z master ($($headSha.Substring(0,8)))"
}

# --- wpisy do drzewa: nowe nazwy + usuniecie starych ---
$entries = @()
foreach ($f in $files) {
  $src = Join-Path $LocalDir $f
  if (-not (Test-Path -LiteralPath $src)) { Write-Host "BRAK pliku: $src" -ForegroundColor Red; exit 1 }
  $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($src))
  $blob = Api "https://api.github.com/repos/$ForkRepo/git/blobs" "Post" @{ content = $b64; encoding = "base64" }
  Write-Host "blob  $f -> $($blob.sha.Substring(0,8))"
  $entries += ,@{ path = "$Dir/$f"; mode = "100644"; type = "blob"; sha = $blob.sha }
}
# skasuj stare, zle nazwane pliki jesli istnialy
$entries += ,@{ path = "$Dir/TZNSECVIRUS.yaml"; mode = "000000"; type = "blob"; sha = $EMPTY_BLOB }
$entries += ,@{ path = "$Dir/TZNSECVIRUS.installer.yaml"; mode = "000000"; type = "blob"; sha = $EMPTY_BLOB }
$entries += ,@{ path = "$Dir/TZNSECVIRUS.locale.pl-PL.yaml"; mode = "000000"; type = "blob"; sha = $EMPTY_BLOB }

$tree = Api "https://api.github.com/repos/$ForkRepo/git/trees" "Post" @{ base_tree = $headSha; tree = $entries }
Write-Host "tree  -> $($tree.sha.Substring(0,8))"

$msg = if ($tree.sha -eq $headSha) { "Retry: poprawne nazwy plikow manifestu" } else { "New package: $ID version $Version" }
$commit = Api "https://api.github.com/repos/$ForkRepo/git/commits" "Post" @{
  message = $msg; tree = $tree.sha; parents = @($headSha)
}
Write-Host "commit -> $($commit.sha.Substring(0,8))"

try {
  Api "https://api.github.com/repos/$ForkRepo/git/refs" "Post" @{ ref = "refs/heads/$Branch"; sha = $commit.sha } | Out-Null
} catch {
  Api "https://api.github.com/repos/$ForkRepo/git/refs/heads/$Branch" "Patch" @{ sha = $commit.sha; force = $true } | Out-Null
}
Write-Host "galez -> $Branch"

# --- utworz PR (jesli nie istnieje) ---
try {
  $exists = Invoke-RestMethod -Uri "https://api.github.com/repos/$UpRepo/pulls?head=tznsec:$Branch&state=all" -Headers $h
  if ($exists.Count -gt 0) {
    Write-Host ""
    Write-Host "PR juz istnieje: $($exists[0].html_url)" -ForegroundColor Green
    Write-Host "commit: $($commit.sha)"
    exit 0
  }
} catch {}

$pr = Api "https://api.github.com/repos/$UpRepo/pulls" "Post" @{
  title = "New package: $ID version $Version"
  head  = "tznsec:$Branch"
  base  = "master"
  body  = "New package: TZNSECVIRUS $Version`n`nAplikacja desktopowa (Rust + WebView) do skanowania bezpieczenstwa komputera z analiza AI.`n`n- Portable installer (x64)`n- SHA256 zweryfikowany`n- Autor: tznsec"
}
Write-Host ""
Write-Host "PR: $($pr.html_url)" -ForegroundColor Green