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
  # 引擎版本事實源：scripts/versions.env（Dockerfile ARG / CI 直接讀取）。
  # 此處 default 須與 versions.env 同步——bump 引擎版本時三處一起改（ADR-012 checklist）。
  [string]$SyftVersion = "1.45.1",
  [string]$GrypeVersion = "0.114.0",
  [string]$DbPath = "$env:LOCALAPPDATA\grype\db",
  [switch]$SkipDb,
  [switch]$WithoutCbom
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
  # 下載即釘版（URL 內含版本），此處再驗一次解出的 exe 自報版本，
  # 與 Linux 側 require_engine_version 對稱（release-prep 複審 major #5/#9 的補齊）
  $got = (& "$Bundle\bin\$name.exe" --version 2>$null | Select-Object -First 1) -replace "^$name\s+", ''
  if ($got -ne $ver) { throw "$name self-reports '$got' but pinned version is '$ver'" }
  Say "$name $got verified"
}
Get-Engine "syft" $SyftVersion
Get-Engine "grype" $GrypeVersion

# 引擎釘選版本的單一事實源（與 package.sh 一致）
# 與 build.rs / package.sh 同一規則：恰一行且為 數字(.數字)+——取第一行或退回 "unknown"
# 會讓 NOTICE 與報表上的引擎版本靜默分歧（T909 第二輪複審 build#1）。
$TheiaLines = @(Select-String -Path "$PSScriptRoot\versions.env" -Pattern '^THEIA_VERSION=')
if ($TheiaLines.Count -ne 1) { throw "versions.env must contain exactly one THEIA_VERSION= line (found $($TheiaLines.Count))" }
$TheiaVersion = ($TheiaLines[0].Line -replace '^THEIA_VERSION=', '').Trim()
if ($TheiaVersion -notmatch '^[0-9]+(\.[0-9]+)+$') { throw "THEIA_VERSION '$TheiaVersion' is not digits(.digits)+" }

# 2b) CBOM 引擎 cbomkit-theia（ADR-013 決策 1）
#
# 注意：**不可**比照上方從 GitHub release 下載——ADR-013 明定自源碼建置、不依賴上游
# release binary。Windows 版須由我方 CI（GOOS=windows 交叉編譯，參數見 versions.env 註解）
# 產出後作為釋出資產，再由本腳本取用；在該資產就緒前，Windows 包不含 CBOM 引擎，
# `--cbom` 會降級為「未盤點」，不影響 SBOM 與弱點比對。
$TheiaExe = Join-Path $PSScriptRoot "..\dist\cbomkit-theia.exe"
if (Test-Path $TheiaExe) {
  Say "collect cbomkit-theia (self-built artifact)"
  Copy-Item $TheiaExe "$Bundle\bin\cbomkit-theia.exe"
} elseif ($WithoutCbom) {
  Say "WithoutCbom: bundle intentionally ships without the CBOM engine (--cbom degrades)"
} else {
  # fail-hard（與 Linux 側對稱）：原本 WARN 續跑會靜默出一個少引擎的「完整」包，
  # 而 CHANGELOG 宣稱「打包 fail-hard」只有 Linux 為真——文件替不存在的控制背書
  #（release-prep 複審 major #5/#9）。刻意不含時以 -WithoutCbom 顯式豁免。
  throw "cbomkit-theia.exe not found at dist\. Build it first, or pass -WithoutCbom explicitly."
}

# 3) grype DB 離線快照（跨平台通用）
if (-not $SkipDb) {
  if (Test-Path $DbPath) {
    Say "copy grype DB snapshot ($DbPath)"
    Copy-Item -Recurse -Force "$DbPath\*" "$Bundle\db\"
  } else {
    # fail-hard（與 Linux 側對稱；-SkipDb 為顯式豁免）：原本只 Warning 續跑，
    # 會出一個無 DB 的「完整」簽章包，場域拆包才發現比對整條不能用
    throw "grype DB not found at $DbPath. Run 'grype db update' first, or pass -SkipDb explicitly."
  }
} else { Say "skip DB (smoke)" }

# 4) 自產 SBOM（dogfooding，FR-009）
Say "self-SBOM"
& "$Bundle\bin\syft.exe" scan "dir:$Root" --exclude './frontend/node_modules/**' `
  --exclude './target/**' --exclude './delivery/**' -o cyclonedx-json -q |
  Out-File -Encoding utf8 "$Bundle\cytrace.sbom.cdx.json"

# 4b) 變更記錄（與 Linux 包對稱）
Say "collect CHANGELOG"
Copy-Item "$Root\CHANGELOG.md" "$Bundle\CHANGELOG.md"

# 5) NOTICE（theia 段落依**實際是否收進包內**輸出，與 package.sh 等價）
if (Test-Path "$Bundle\bin\cbomkit-theia.exe") {
  $TheiaNotice = @"
  - CBOMkit-theia (PQCA / Linux Foundation, Apache-2.0) - cryptographic asset inventory (CBOM; ADR-013)
    Built from source (tag v$TheiaVersion), not an upstream release binary.
    Its dependencies include the following non-Apache-2.0 components:
      * gitleaks v8 (MIT), gitleaks/go-gitdiff (MIT) - embedded secret detection rules
      * MPL-2.0 (file-level weak copyleft): hashicorp/golang-lru, hashicorp/go-version,
        cyphar/filepath-securejoin
"@
} else {
  $TheiaNotice = "  (This bundle does not include the CBOM engine; cytrace --cbom degrades to `"not inventoried`".)"
}

@"
CyTrace $Version - Third-party NOTICE
Bundled tools (unmodified). See each upstream vendor directory for the full
dependency and license list; this product distributes build artifacts only
and the source was not modified (Apache-2.0 section 4(b)):
  - Syft  (Anchore, Apache-2.0) - SBOM generation
  - Grype (Anchore, Apache-2.0) - vulnerability matching
$TheiaNotice

TLS for the web service mode (cytrace serve, ADR-011) is provided by rustls + ring:
  - ring - licensed under a mix of ISC and OpenSSL/BoringSSL terms (see the ring crate
    LICENSE). Licenses and versions of all Rust dependencies (tokio/axum/argon2 and the
    rest) are in the bundled cytrace.sbom.cdx.json.

Supply chain: no China-sourced dependencies (e.g. OpenSCA-cli).
  Scope of this statement: dependency source domains, copyright notices and maintaining
  organizations; it does not cover the nationality or residence of individual contributors
  (see ADR-013 "scope of the no-China-sourced rule").
Rust dependencies are gated in CI by cargo-deny (license / source allowlist).
"@ | Out-File -Encoding utf8 "$Bundle\NOTICE"

# 6) 離線執行 wrapper（固定用包內引擎與 DB、強制離線）
@'
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:Path = "$here\bin;$env:Path"
$env:GRYPE_DB_CACHE_DIR = "$here\db"
$env:GRYPE_DB_AUTO_UPDATE = 'false'
$env:GRYPE_DB_VALIDATE_AGE = 'false'
$env:GRYPE_CHECK_FOR_APP_UPDATE = 'false'
$env:SYFT_CHECK_FOR_APP_UPDATE = 'false'
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
