#!/usr/bin/env python3
"""打包腳本 NOTICE 對帳（ADR-013 / 供應鏈純淨鐵則）。

`package.sh`（Linux）與 `package.ps1`（Windows）各自生成 NOTICE，
兩份是分別維護的文字——**改一邊忘一邊就會出一個授權聲明不實的交付包**。
第六輪複審 finding J 即為此：ps1 整段漏了 ring 的 ISC + OpenSSL/BoringSSL
混合授權聲明，而 Windows 交付同樣含 cytrace serve、同樣連結 ring。

本檢查不比對逐字（兩份本就一中一英），只要求下列**法律上必須出現的實體**
在兩份 NOTICE 中皆被提及。CI 的 windows-package job 另有對「產出物」的斷言；
本檢查在 lint 階段先擋住原始碼層的不對稱，無須跑完整打包。

**只比對 NOTICE 文字區段，不比對整個腳本檔**（第七輪複審 blocker）：
初版對整檔做 `re.search`，於是 `Syft` 命中 ps1 的 `.PARAMETER SyftVersion`、
`不含 CBOM 引擎` 命中 sh 的 `echo "…WITHOUT_CBOM=1…"`——把 NOTICE 裡的對應段
整段刪掉，檢查依然綠。一個擋不到它宣稱擋的東西的 gate，比沒有 gate 更糟，
因為它會被當成證據。故本版先切出 here-doc / here-string，再比對；
並以 `--self-test` 對每一列做變異驗證，證明沒有白列。
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SH = ROOT / "scripts" / "package.sh"
PS1 = ROOT / "scripts" / "package.ps1"

# 每一項：(說明, sh 需含的 pattern, ps1 需含的 pattern)
# 分列兩欄是因為兩份 NOTICE 一中一英；共用的專有名詞才寫同一字串。
REQUIRED = [
    ("Syft 授權", r"Syft", r"Syft"),
    ("Grype 授權", r"Grype", r"Grype"),
    ("theia 授權（條件段）", r"CBOMkit-theia", r"CBOMkit-theia"),
    ("theia 相依 MPL-2.0 標示", r"MPL-2\.0", r"MPL-2\.0"),
    ("theia 相依 gitleaks MIT 標示", r"gitleaks", r"gitleaks"),
    ("theia 缺席時的明示降級", r"不含 CBOM 引擎", r"does not include the CBOM engine"),
    ("ring 混合授權（ISC + OpenSSL/BoringSSL）", r"\bring\b", r"\bring\b"),
    ("ring 的 OpenSSL/BoringSSL 條款", r"OpenSSL/BoringSSL", r"OpenSSL/BoringSSL"),
    ("rustls（TLS 提供者）", r"rustls", r"rustls"),
    ("自產 SBOM 交叉引用", r"cytrace\.sbom\.cdx\.json", r"cytrace\.sbom\.cdx\.json"),
    ("禁中國來源宣告", r"OpenSCA-cli", r"OpenSCA-cli"),
    ("該宣告的涵蓋範圍註記", r"國籍", r"does not cover the nationality"),
    ("cargo-deny 把關聲明", r"cargo-deny", r"cargo-deny"),
]

# NOTICE 區段的界線。兩支腳本都是「條件段（theia）」＋「主體」兩塊，
# 條件段的 else 分支是單行賦值，故一併以賦值列的字串內容納入。
SH_BLOCKS = [
    # THEIA_NOTICE="$(cat <<THEIA … THEIA )"
    (r'THEIA_NOTICE="\$\(cat <<THEIA\n', r"\nTHEIA\n"),
    # cat > "$BUNDLE/NOTICE" <<NOTICE … NOTICE
    (r'cat > "\$BUNDLE/NOTICE" <<NOTICE\n', r"\nNOTICE\n"),
]
SH_INLINE = r'^\s*THEIA_NOTICE="([^"]*)"\s*$'

PS1_BLOCKS = [
    # $TheiaNotice = @" … "@
    (r'\$TheiaNotice = @"\n', r'\n"@\n'),
    # @" … "@ | Out-File … NOTICE
    (r'@"\nCyTrace ', r'\n"@ \| Out-File'),
]
PS1_INLINE = r"^\s*\$TheiaNotice = \"(.*)\"\s*$"


def extract(text: str, blocks, inline_pat: str) -> str:
    """抽出會成為 NOTICE 內容的文字；抽不到任何區段即為錯誤（不得靜默回空字串）。"""
    parts = []
    for start, end in blocks:
        m = re.search(start + r"(.*?)" + end, text, re.S)
        if m:
            parts.append(m.group(1))
    for m in re.finditer(inline_pat, text, re.M):
        parts.append(m.group(1))
    return "\n".join(parts)


def check(sh_notice: str, ps1_notice: str) -> list[str]:
    """回傳缺漏清單（空清單 = 通過）。"""
    missing = []
    for label, sh_pat, ps1_pat in REQUIRED:
        if not re.search(sh_pat, sh_notice):
            missing.append(f"package.sh 的 NOTICE 缺「{label}」")
        if not re.search(ps1_pat, ps1_notice):
            missing.append(f"package.ps1 的 NOTICE 缺「{label}」")
    return missing


def load() -> tuple[str, str]:
    for path in (SH, PS1):
        if not path.exists():
            print(f"✗ 缺少打包腳本: {path}")
            sys.exit(1)
    sh_notice = extract(SH.read_text(encoding="utf-8"), SH_BLOCKS, SH_INLINE)
    ps1_notice = extract(PS1.read_text(encoding="utf-8"), PS1_BLOCKS, PS1_INLINE)
    return sh_notice, ps1_notice


# ── 抽取正確性的哨兵 ──
#
# 抽取一旦失效（腳本改寫 here-doc 形式、正則沒跟上）就會退回空字串或整檔，
# 兩種都會讓本檢查失去意義：空字串 → 全部缺漏（吵但安全）；整檔 → 全部通過（危險）。
# 故明確斷言「這些 NOTICE 之外的字串不得出現在抽取結果裡」。
OUTSIDE_SH = [
    "WITHOUT_CBOM=1：本包刻意不含",  # 打包流程的 echo，非 NOTICE
    "syft scan",  # 產 SBOM 的指令
    "GRYPE_DB_CACHE_DIR",  # wrapper 內容
]
OUTSIDE_PS1 = [
    ".PARAMETER",  # 註解區塊
    "Get-Engine",  # 下載函式
    "Invoke-WebRequest",  # 下載指令
]


def assert_extraction_is_sound(sh_notice: str, ps1_notice: str) -> list[str]:
    problems = []
    if not sh_notice.strip():
        problems.append("package.sh 的 NOTICE 區段抽取為空——here-doc 形式可能已改變")
    if not ps1_notice.strip():
        problems.append("package.ps1 的 NOTICE 區段抽取為空——here-string 形式可能已改變")
    for needle in OUTSIDE_SH:
        if needle in sh_notice:
            problems.append(f"package.sh 抽取範圍過寬：含 NOTICE 之外的 {needle!r}")
    for needle in OUTSIDE_PS1:
        if needle in ps1_notice:
            problems.append(f"package.ps1 抽取範圍過寬：含 NOTICE 之外的 {needle!r}")
    return problems


def self_test(sh_notice: str, ps1_notice: str) -> int:
    """變異測試：逐列從 NOTICE 抹去該實體，確認本檢查**必定轉紅**。

    白列（無論如何都會通過的列）在此會現形——它是假的機械支撐，
    正是第七輪複審抓到初版的那個錯法。
    """
    print("自我測試：逐列變異，確認每一列都真的有把關作用")
    dead = []
    for label, sh_pat, ps1_pat in REQUIRED:
        for side, notice, pat in (
            ("package.sh", sh_notice, sh_pat),
            ("package.ps1", ps1_notice, ps1_pat),
        ):
            mutated = re.sub(pat, "＜已抹去＞", notice)
            if mutated == notice:
                dead.append(f"{side}「{label}」：pattern 在 NOTICE 中無命中，變異無效")
                continue
            if side == "package.sh":
                missing = check(mutated, ps1_notice)
            else:
                missing = check(sh_notice, mutated)
            if not missing:
                dead.append(f"{side}「{label}」：抹去後檢查仍通過 → 白列")
    if dead:
        print("✗ 下列項目不具把關作用：")
        for d in dead:
            print(f"    - {d}")
        return 1
    print(f"✓ 自我測試通過（{len(REQUIRED)} 列 × 2 平台 = {len(REQUIRED) * 2} 個變異全數轉紅）")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="打包腳本 NOTICE 對帳")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="對每一列做變異，驗證本檢查確實擋得住缺漏（無白列）",
    )
    args = ap.parse_args()

    sh_notice, ps1_notice = load()

    problems = assert_extraction_is_sound(sh_notice, ps1_notice)
    if problems:
        print("✗ NOTICE 區段抽取不可信，檢查結論無效：")
        for p in problems:
            print(f"    - {p}")
        return 1

    if args.self_test:
        return self_test(sh_notice, ps1_notice)

    missing = check(sh_notice, ps1_notice)
    if missing:
        print("✗ 兩平台 NOTICE 不對稱——會出授權聲明不實的交付包：")
        for m in missing:
            print(f"    - {m}")
        return 1

    print(
        f"✓ NOTICE 對帳通過（{len(REQUIRED)} 項法律必要實體，Linux / Windows 皆具備；"
        f"比對範圍為 NOTICE 區段 {len(sh_notice)} / {len(ps1_notice)} 字元）"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
