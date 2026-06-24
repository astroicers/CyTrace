<#
.SYNOPSIS
  CyTrace Windows 離線安裝包組裝（ADR-010 / ADR-007 / DELIVERY_SOP）。
.DESCRIPTION
  從原始碼 build cytrace.exe，收集釘選版 syft.exe / grype.exe 與 grype DB 離線快照，
  產自產 SBOM、NOTICE、SHA256SUMS 與離線執行 wrapper，組成單一可攜安裝包。
  對應 air-gapped Windows 目標機。為 package.sh 的 Windows 對應版。
.PARAMETER OutDir
  輸出根目錄（預設 .\delivery）。
.PARAMETER SyftVersion / GrypeVersion
  釘選引擎版本（與 Linux 版一致）。
.PARAMETER DbPath
  grype DB 來源（預設 $env:LOCALAPPDATA\grype\db；需先在有網段 grype db update）。
.PARAMETER SkipDb
  跳過 1.7GB DB 複製（CI 冒煙用；產物結構/wrapper/SHA256SUMS 仍完整）。
.EXAMPLE
  pwsh scripts/package.ps1
  pwsh scripts/package.ps1 -SkipDb        # CI 冒煙
#>
[CmdletBinding()]
param(
  [string]$OutDir = "delivery",
  [string]$SyftVersion = "1.45.1",
  [string]$GrypeVersion = "0.114.0",
  [string]$DbPath = "$env:LOCALAPPDATA\grype\db",
  [switch]$SkipDb
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Target = "x86_64-pc-windows-msvc"
$Version = (Select-String -Path "$Root\Cargo.toml" -Pattern '^version\s*=\s*"(.*)"' |
  Select-Object -First 1).Matches.Groups[1].Value
$Bundle = Join-Path $Root "$OutDir\cytrace-$Version-windows"

function Say($m) { Write-Host "  -> $m" }

Write-Host "Assembling CyTrace $Version (Windows) -> $Bundle"
if (Test-Path $Bundle) { Remove-Item -Recurse -Force $Bundle }
New-Item -ItemType Directory -Force -Path "$Bundle\bin", "$Bundle\db" | Out-Null

# 1) cytrace.exe（靜態 CRT，單檔零依賴）
Say "build cytrace.exe ($Target)"
$env:RUSTFLAGS = "-C target-feature=+crt-static"
rustup target add $Target | Out-Null
Push-Location $Root
cargo build --release --locked --target $Target -p cytrace-cli
Pop-Location
Copy-Item "$Root\target\$Target\release\cytrace.exe" "$Bundle\bin\cytrace.exe"

# 2) 釘選引擎（從 Anchore GitHub release 取 Windows 版）
function Get-Engine($name, $ver) {
  $zip = Join-Path $env:TEMP "$name`_$ver`_windows_amd64.zip"
  $url = "https://github.com/anchore/$name/releases/download/v$ver/$name`_$ver`_windows_amd64.zip"
  Say "download $name $ver"
  Invoke-WebRequest -Uri $url -OutFile $zip
  $ex = Join-Path $env:TEMP "$name-$ver-win"
  if (Test-Path $ex) { Remove-Item -Recurse -Force $ex }
  Expand-Archive -Path $zip -DestinationPath $ex -Force
  Copy-Item (Join-Path $ex "$name.exe") "$Bundle\bin\$name.exe"
}
Get-Engine "syft" $SyftVersion
Get-Engine "grype" $GrypeVersion

# 3) grype DB 離線快照（跨平台通用）
if (-not $SkipDb) {
  if (Test-Path $DbPath) {
    Say "copy grype DB snapshot ($DbPath)"
    Copy-Item -Recurse -Force "$DbPath\*" "$Bundle\db\"
  } else {
    Write-Warning "grype DB not found at $DbPath; run 'grype db update' first (或用 -SkipDb)"
  }
} else { Say "skip DB (smoke)" }

# 4) 自產 SBOM（dogfooding，FR-009）
Say "self-SBOM"
& "$Bundle\bin\syft.exe" scan "dir:$Root" --exclude './frontend/node_modules/**' `
  --exclude './target/**' --exclude './delivery/**' -o cyclonedx-json -q |
  Out-File -Encoding utf8 "$Bundle\cytrace.sbom.cdx.json"

# 5) NOTICE
@"
CyTrace $Version - Third-party NOTICE
Bundled Apache-2.0 tools (unmodified): Syft, Grype (Anchore).
Rust dependency licenses: see cytrace.sbom.cdx.json.
Supply chain: no China-sourced dependencies (e.g. OpenSCA-cli).
"@ | Out-File -Encoding utf8 "$Bundle\NOTICE"

# 6) 離線執行 wrapper（固定用包內引擎與 DB、強制離線）
@'
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:Path = "$here\bin;$env:Path"
$env:GRYPE_DB_CACHE_DIR = "$here\db"
$env:GRYPE_DB_AUTO_UPDATE = 'false'
$env:GRYPE_DB_VALIDATE_AGE = 'false'
& "$here\bin\cytrace.exe" @args
exit $LASTEXITCODE
'@ | Out-File -Encoding utf8 "$Bundle\cytrace-offline.ps1"

# 7) SHA256SUMS（完整性）
Say "SHA256SUMS"
Push-Location $Bundle
Get-ChildItem -Recurse -File | Where-Object { $_.Name -ne 'SHA256SUMS' } | ForEach-Object {
  $rel = Resolve-Path -Relative $_.FullName
  "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $rel"
} | Out-File -Encoding ascii "SHA256SUMS"
Pop-Location

Write-Host "DONE: $Bundle"
