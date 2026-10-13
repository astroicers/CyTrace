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
  跳過數 GB 的 DB 複製（CI 冒煙用；產物結構/wrapper/SHA256SUMS 仍完整）。
.PARAMETER CytraceExe
  已建好的 cytrace.exe（例如 GitHub Release 的 cytrace-x86_64-windows.exe）。給了就不在本機編譯，
  建置機不需要 Rust 與 Visual Studio Build Tools；腳本先核對它自報的版本等於 Cargo.toml，不符即中止。
  Release 的 exe 由 release workflow 以相同條件編譯（msvc、crt-static、--locked、釘選 toolchain），
  其真實性另以已簽章的 Release SHA256SUMS 核對（DELIVERY_SOP §2）。
  包內的 CHANGELOG、自產 SBOM、引擎與 theia 的版本釘選（versions.env）取自工作樹，故工作樹必須正好停在
  tag v<版本>，且除了本腳本以外沒有已追蹤的修改，否則中止——不然包內內容描述的不是那支 exe。
  本腳本可以比被打包的版本新（例如以 main 的腳本打包 v0.6.0）。注意 NOTICE 與 cytrace-offline wrapper 的內容
  由本腳本產生；換用較新的腳本前，先檢視它與 tag 版本的差異（DELIVERY_SOP §2）。
.PARAMETER AllowUntaggedTree
  僅供 CI：略過 -CytraceExe 的 tag 檢查（CI 的 checkout 不在 tag 上）。正式交付不得使用。
.EXAMPLE
  pwsh scripts/package.ps1
  pwsh scripts/package.ps1 -SkipDb        # CI 冒煙
  pwsh scripts/package.ps1 -CytraceExe C:\cytrace-build\cytrace-x86_64-windows.exe -DbPath C:\cytrace-build\grype-db
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
  [switch]$WithoutCbom,
  [string]$CytraceExe = "",
  [switch]$AllowUntaggedTree
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Target = "x86_64-pc-windows-msvc"
$Version = (Select-String -Path "$Root\Cargo.toml" -Pattern '^version\s*=\s*"(.*)"' |
  Select-Object -First 1).Matches.Groups[1].Value
$Bundle = Join-Path $Root "$OutDir\cytrace-$Version-windows"

function Say($m) { Write-Host "  -> $m" }

# versions.env 以嚴格演算法讀入一次，供下方引擎版本檢查與後段 THEIA 解析共用。
# 不用 Get-Content：它把裸 CR 也當換行、預設編碼隨 PowerShell 版本與系統語系而異。
$VersionsBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\versions.env")
if ($VersionsBytes -contains 0) { throw "versions.env contains a NUL byte" }
$VersionsText = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($VersionsBytes)  # 非 UTF-8 即 throw

# 引擎版本以工作樹的 versions.env 為準：腳本參數（預設值）與它不符即中止（不論是否使用 -CytraceExe；
# 使用者 2026-10-13 裁定）。打包腳本可能比被打包的 tag 新，只信腳本預設值的話，main 升過引擎後再打包舊 tag
# 會靜默收進新版引擎——版本漂移的 syft 會讓場域的 grype 讀不懂 SBOM（DELIVERY_SOP §2）。
# 同時把「三處一起改」從註解變成機械檢查。在刪除舊包之前檢查。
$Pinned = @{}
foreach ($line in ($VersionsText -split "`n" | ForEach-Object { $_ -replace "`r$", '' })) {
  if ($line -cmatch '^(SYFT_VERSION|GRYPE_VERSION)=(.+)$') { $Pinned[$Matches[1]] = $Matches[2].Trim() }
}
if ($Pinned['SYFT_VERSION'] -ne $SyftVersion -or $Pinned['GRYPE_VERSION'] -ne $GrypeVersion) {
  throw "Engine versions differ from scripts/versions.env: syft $SyftVersion vs '$($Pinned['SYFT_VERSION'])', grype $GrypeVersion vs '$($Pinned['GRYPE_VERSION'])'"
}

# 預建 cytrace.exe 的前置檢查——在刪除舊包之前做：失敗時不毀掉上一次的完好包、不留半套目錄
$PrebuiltExe = $null
if ($CytraceExe) {
  if (-not (Test-Path -LiteralPath $CytraceExe -PathType Leaf)) { throw "CytraceExe not found (or not a file): $CytraceExe" }
  # 解析成完整路徑再執行：只寫檔名時 `&` 會走 PATH，驗到的可能不是要複製的那支
  $PrebuiltExe = (Resolve-Path -LiteralPath $CytraceExe).ProviderPath
  # 包內除了 exe，CHANGELOG／自產 SBOM／引擎與 theia 的版本釘選都取自工作樹：工作樹必須就是該版的 tag。
  # 否則版號相同、內容不同（例如 main 已含 vX.Y.Z 之後的修正而版號未變），包內內容描述的就不是那支 exe
  # 例外只有本腳本：打包工具可以比被打包的版本新（引擎版本已由上方對 versions.env 把關）
  if ($AllowUntaggedTree) {
    Say "WARNING: -AllowUntaggedTree (CI only) - source tree tag check skipped; not for delivery"
  } else {
    $tags = @(& git -C $Root tag --points-at HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or $tags -notcontains "v$Version") {
      throw "With -CytraceExe the source tree must be checked out at tag v$Version (git checkout v$Version); HEAD tags: '$($tags -join ',')'"
    }
    $dirty = @(& git -C $Root status --porcelain --untracked-files=no -- . ':(exclude)scripts/package.ps1')
    if ($LASTEXITCODE -ne 0) { throw "git status failed (exit $LASTEXITCODE)" }
    if ($dirty.Count -gt 0) {
      throw "With -CytraceExe the source tree must have no tracked modifications (other than scripts/package.ps1): $($dirty -join '; ')"
    }
  }
  # 先存 exit code 再篩選輸出：管線被提前結束時 $LASTEXITCODE 的值不可靠
  $out = @(& $PrebuiltExe --version 2>&1)
  $code = $LASTEXITCODE
  if ($code -ne 0) { throw "CytraceExe --version failed (exit $code)" }
  $reported = "$($out | Select-Object -First 1)".Trim()
  if ($reported -ne "cytrace $Version") {
    throw "CytraceExe reports '$reported' but Cargo.toml version is '$Version'"
  }
}

Write-Host "Assembling CyTrace $Version (Windows) -> $Bundle"
if (Test-Path $Bundle) { Remove-Item -Recurse -Force $Bundle }
New-Item -ItemType Directory -Force -Path "$Bundle\bin", "$Bundle\db" | Out-Null

# 1) cytrace.exe（靜態 CRT，單檔零依賴）
if ($PrebuiltExe) {
  # 預建 exe：不編譯，原樣收入（前置檢查已核對版本與 tag；真實性由已簽章的 Release SHA256SUMS 另行核對）
  Say "use prebuilt cytrace.exe ($PrebuiltExe; $reported)"
  Copy-Item -LiteralPath $PrebuiltExe "$Bundle\bin\cytrace.exe"
} else {
  Say "build cytrace.exe ($Target)"
  $env:RUSTFLAGS = "-C target-feature=+crt-static"
  rustup target add $Target | Out-Null
  Push-Location $Root
  # touch：同路徑重建時 cargo 依 mtime 判新鮮，versions.env 若比上次建置舊，build script 不重跑、
  # 報表沿用舊的 theia 版號（T909 第三、四輪複審 build#0／build#4；Linux 側 package.sh 同理）
  (Get-Item "$PSScriptRoot\versions.env").LastWriteTime = Get-Date
  cargo build --release --locked --target $Target -p cytrace-cli
  # 原生指令失敗不會自動 throw——不檢查的話，build.rs 拒收 versions.env（或任何編譯錯誤）時
  # 照樣往下打包上一次的舊 binary（第四輪複審 build#3）
  if ($LASTEXITCODE -ne 0) { Pop-Location; throw "cargo build failed (exit $LASTEXITCODE)" }
  Pop-Location
  Copy-Item "$Root\target\$Target\release\cytrace.exe" "$Bundle\bin\cytrace.exe"
}

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
# 與 build.rs（crates/cytrace-core/theia_version_rule.rs）、package.sh（check-theia-version.sh）
# 同一演算法：嚴格 UTF-8、不含 NUL、以 LF 切行並去一個行尾 CR、註解行（行首 ASCII 空白後接 #）
# 不算、其餘只准一行以 ASCII 詞邊界提到 THEIA_VERSION 且逐字是 THEIA_VERSION=<數字(.數字)+>。
# 本實作是對照實作：只在 windows-package CI job 以真實 versions.env 執行過，沒有對樣本表對帳。
# $VersionsText 已在前置檢查讀入（嚴格 UTF-8、不含 NUL；見該處）。
$TheiaLines = @($VersionsText -split "`n" | ForEach-Object { $_ -replace "`r$", '' } |
  Where-Object { $_ -cnotmatch '^[ \t\x0B\x0C\r]*#' -and $_ -cmatch '(?<![A-Za-z0-9_])THEIA_VERSION(?![A-Za-z0-9_])' })
if ($TheiaLines.Count -ne 1) { throw "versions.env: exactly one non-comment line may mention THEIA_VERSION (found $($TheiaLines.Count))" }
if ($TheiaLines[0] -cnotmatch '^THEIA_VERSION=([0-9]+(\.[0-9]+)+)$') { throw "versions.env: THEIA_VERSION line must be exactly THEIA_VERSION=<digits(.digits)+>: '$($TheiaLines[0])'" }
$TheiaVersion = $Matches[1]

# 2b) CBOM 引擎 cbomkit-theia（ADR-013 決策 1、T911）
#
# 注意：**不可**比照上方從 GitHub release 下載上游 binary——ADR-013 明定自源碼建置。
# Windows 版由我方以 Dockerfile 的 theia-builder-windows stage 交叉編譯
# （`scripts/build-theia.sh dist windows`，或取我方 release 的 cbomkit-theia-windows-amd64.exe），
# 放到 dist\ 後由本腳本取用，並比對 versions.env 的 THEIA_WINDOWS_AMD64_SHA256——不符即中止。
$TheiaShaLines = @($VersionsText -split "`n" | ForEach-Object { $_ -replace "`r$", '' } |
  Where-Object { $_ -cnotmatch '^[ \t\x0B\x0C\r]*#' -and $_ -cmatch '(?<![A-Za-z0-9_])THEIA_WINDOWS_AMD64_SHA256(?![A-Za-z0-9_])' })
if ($TheiaShaLines.Count -ne 1 -or $TheiaShaLines[0] -cnotmatch '^THEIA_WINDOWS_AMD64_SHA256=([0-9a-f]{64})$') {
  throw "versions.env: exactly one line THEIA_WINDOWS_AMD64_SHA256=<64 lowercase hex> is required"
}
$TheiaWindowsSha = $Matches[1]
$TheiaExe = Join-Path $PSScriptRoot "..\dist\cbomkit-theia.exe"
if (Test-Path $TheiaExe) {
  $got = (Get-FileHash -Algorithm SHA256 $TheiaExe).Hash.ToLowerInvariant()
  if ($got -ne $TheiaWindowsSha) {
    throw "dist\cbomkit-theia.exe SHA256 $got != pinned $TheiaWindowsSha (versions.env) - not our reproducible build"
  }
  Say "collect cbomkit-theia (self-built, SHA256 verified)"
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

# 8) 簽章（真實性，可選）— 需 minisign 與私鑰（DELIVERY_SOP §3；與 package.sh 對等，T920）
$minisign = Get-Command minisign -ErrorAction SilentlyContinue
if ($minisign -and $env:CYTRACE_MINISIGN_SECKEY) {
  Say "minisign sign SHA256SUMS"
  & $minisign.Source -Sm "$Bundle\SHA256SUMS" -s $env:CYTRACE_MINISIGN_SECKEY | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "minisign signing failed (exit $LASTEXITCODE)" }
} else {
  # 執行期字串維持 ASCII：Windows PowerShell 5.1 讀無 BOM 的 UTF-8 腳本時非 ASCII 會亂碼
  Write-Host "  skip signing (no minisign on PATH or CYTRACE_MINISIGN_SECKEY unset); see DELIVERY_SOP section 3"
}

Write-Host "DONE: $Bundle"
