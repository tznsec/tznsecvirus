$ErrorActionPreference = "Stop"

# Token ustaw w srodowisku, NIGDY w kodzie (GitHub blokuje push z sekretem):
#   $env:GITHUB_TOKEN = "ghp_..."
if (-not $env:GITHUB_TOKEN) {
  Write-Host "Brak $env:GITHUB_TOKEN - ustaw token z uprawnieniami (contents:write, pull_requests:write)" -ForegroundColor Red
  exit 1
}
$token = $env:GITHUB_TOKEN
$h = @{ Authorization = "Bearer $token"; Accept = "application/vnd.github+json"; "User-Agent" = "tznsec" }
$dir = "manifests/t/tznsecvirus/TZNSECVIRUS/2.0.0"
$files = @("TZNSECVIRUS.yaml","TZNSECVIRUS.installer.yaml","TZNSECVIRUS.locale.pl-PL.yaml")

function Post($url, $obj) {
  $json = $obj | ConvertTo-Json -Depth 10 -Compress
  try {
    return Invoke-RestMethod -Uri $url -Method Post -Headers $h -Body $json -ContentType "application/json" -TimeoutSec 120
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
      Write-Host ("HTTP {0}: {1}" -f [int]$resp.StatusCode, $sr.ReadToEnd())
    } else { Write-Host ("ERR: " + $_.Exception.Message) }
    throw
  }
}

$ref = Invoke-RestMethod -Uri "https://api.github.com/repos/tznsec/winget-pkgs/git/ref/heads/master" -Headers $h
$baseSha = $ref.object.sha
Write-Host "base: $baseSha"

# sprawdz czy juz istnieje galeaz
$branch = "tznsecvirus-tznsecvirus-2.0.0"
try {
  $ex = Invoke-RestMethod -Uri "https://api.github.com/repos/tznsec/winget-pkgs/git/ref/heads/$branch" -Headers $h
  Write-Host "galez juz istnieje: $($ex.object.sha)"
  $baseSha = $ex.object.sha
} catch { Write-Host "galez nie istnieje - tworze" }

# blobs
$entries = @()
foreach ($f in $files) {
  $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes(".\winget\$f"))
  $blob = Post "https://api.github.com/repos/tznsec/winget-pkgs/git/blobs" @{ content = $b64; encoding = "base64" }
  Write-Host "blob $f -> $($blob.sha.Substring(0,8))"
  $entries += ,@{ path = "$dir/$f"; mode = "100644"; type = "blob"; sha = $blob.sha }
}

$tree = Post "https://api.github.com/repos/tznsec/winget-pkgs/git/trees" @{ base_tree = $baseSha; tree = $entries }
Write-Host "tree -> $($tree.sha.Substring(0,8))"

$parent = if ($branch -and (Test-Path "$env:TEMP\did_branch.txt")) { $baseSha } else { $baseSha }
$commit = Post "https://api.github.com/repos/tznsec/winget-pkgs/git/commits" @{
  message = "New package: tznsecvirus.TZNSECVIRUS version 2.0.0"
  tree = $tree.sha
  parents = @($baseSha)
}
Write-Host "commit -> $($commit.sha.Substring(0,8))"

# galeaz
try {
  Post "https://api.github.com/repos/tznsec/winget-pkgs/git/refs" @{ ref = "refs/heads/$branch"; sha = $commit.sha } | Out-Null
  Write-Host "galez utworzona: $branch"
} catch {
  # galeaz istnieje - ustaw nowy sha
  $null = Post "https://api.github.com/repos/tznsec/winget-pkgs/git/refs/heads/$branch" @{ sha = $commit.sha; force = $true }
  Write-Host "galez zaktualizowana"
}

$pr = Post "https://api.github.com/repos/microsoft/winget-pkgs/pulls" @{
  title = "New package: tznsecvirus.TZNSECVIRUS version 2.0.0"
  head = "tznsec:$branch"
  base = "master"
  body = "New package: TZNSECVIRUS 2.0.0`n`nAplikacja desktopowa (Rust + WebView) do skanowania bezpieczenstwa komputera z analiza AI.`n`n- Portable installer (x64)`n- SHA256 zweryfikowany`n- Autor: tznsec"
  draft = $false
}
Write-Host ""
Write-Host "PR: $($pr.html_url)" -ForegroundColor Green