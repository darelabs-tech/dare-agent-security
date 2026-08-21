# Package dare-agent-security release binary + SHA-256 checksums (Windows).
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root
$Version = (Select-String -Path "Cargo.toml" -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches.Groups[1].Value
$OutName = "dare-agent-security-v$Version"
$Stage = Join-Path "dist" $OutName
New-Item -ItemType Directory -Force -Path "dist" | Out-Null
cargo build -p dare-agent-security --release
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
Copy-Item "target\release\dare-agent-security.exe" $Stage
Copy-Item "README.md" $Stage
Copy-Item "docs\quickstart.md" (Join-Path $Stage "QUICKSTART.md")
Copy-Item "docs\product\v1-contract.md" (Join-Path $Stage "V1-CONTRACT.md")
$Zip = Join-Path "dist" "$OutName.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path $Stage -DestinationPath $Zip
$hash = (Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLower()
Set-Content -Path "$Zip.sha256" -Value "$hash  $OutName.zip"
Write-Host "Wrote $Zip and checksum"
