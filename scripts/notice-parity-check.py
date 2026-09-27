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
抽取的正確性由兩項結構性檢查承接（區段數、OUTSIDE needle），
`--verify-sentinels` 對它們做故障注入。
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
    # Apache-2.0 §4(b) 對「是否修改過原始碼」有聲明要求；sh 有、ps1 原本整句缺
    # （第八輪複審 finding I）
    ("未修改原始碼之聲明", r"未修改原始碼", r"source was not modified"),
    ("上游 vendor 目錄指引", r"vendor 目錄", r"vendor directory"),
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


def extract(text: str, blocks, inline_pat: str) -> tuple[str, int, int]:
    """抽出會成為 NOTICE 內容的文字。

    回傳（文字, 命中的 block 數, 命中的 inline 數）。**命中數要回報出去**：
    某個 block pattern 失配時該段會被靜默丟棄，而「整體非空」檢查抓不到
    ——現在不出錯只是靠 REQUIRED 清單的分布碰巧蓋住，不是靠機制
    （第八輪複審 finding H）。
    """
    parts = []
    block_hits = 0
    for start, end in blocks:
        m = re.search(start + r"(.*?)" + end, text, re.S)
        if m:
            parts.append(m.group(1))
            block_hits += 1
    inline_hits = 0
    for m in re.finditer(inline_pat, text, re.M):
        parts.append(m.group(1))
        inline_hits += 1
    return "\n".join(parts), block_hits, inline_hits


def check(sh_notice: str, ps1_notice: str) -> list[str]:
    """回傳缺漏清單（空清單 = 通過）。"""
    missing = []
    for label, sh_pat, ps1_pat in REQUIRED:
        if not re.search(sh_pat, sh_notice):
            missing.append(f"package.sh 的 NOTICE 缺「{label}」")
        if not re.search(ps1_pat, ps1_notice):
            missing.append(f"package.ps1 的 NOTICE 缺「{label}」")
    return missing


def notice_of(text: str, which: str) -> tuple[str, list[str]]:
    """從腳本原文抽出 NOTICE 區段，並回報抽取本身的問題。"""
    if which == "sh":
        blocks, inline, outside = SH_BLOCKS, SH_INLINE, OUTSIDE_SH
    else:
        blocks, inline, outside = PS1_BLOCKS, PS1_INLINE, OUTSIDE_PS1
    notice, block_hits, inline_hits = extract(text, blocks, inline)
    problems = []
    name = "package.sh" if which == "sh" else "package.ps1"
    if block_hits != len(blocks):
        problems.append(
            f"{name}：{len(blocks)} 個 NOTICE 區段只抽到 {block_hits} 個"
            f"——here-doc / here-string 形式可能已改變，該段內容不會被檢查"
        )
    if inline_hits < 1:
        problems.append(f"{name}：theia 缺席時的單行 NOTICE 抽不到")
    if not notice.strip():
        problems.append(f"{name}：NOTICE 區段抽取為空")
    for needle in outside:
        if needle in notice:
            problems.append(f"{name} 抽取範圍過寬：含 NOTICE 之外的 {needle!r}")
    return notice, problems


def load() -> tuple[str, str, list[str]]:
    for path in (SH, PS1):
        if not path.exists():
            print(f"✗ 缺少打包腳本: {path}")
            sys.exit(1)
    sh_notice, sh_problems = notice_of(SH.read_text(encoding="utf-8"), "sh")
    ps1_notice, ps1_problems = notice_of(PS1.read_text(encoding="utf-8"), "ps1")
    return sh_notice, ps1_notice, sh_problems + ps1_problems


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


def verify_sentinels() -> int:
    """驗證**哨兵本身**擋得住抽取退化——這才是白列的防線。

    誠實記錄為什麼不是「對 REQUIRED 逐列做變異」（前兩版都是那樣，兩版都證不出東西）：

    - 第一版變異**抽取後的字串**。`re.sub` 移除 pattern 的所有命中後，隨後的 `re.search`
      依構造必然失敗，故「抹去後仍通過」永不觸發；而「pattern 無命中」早已被正常執行
      蘊含。通過條件 ≡ 正常執行的通過條件（第八輪複審 finding C）。
    - 第二版把變異上移到**打包腳本原文**，以為能把 `extract()` 納入變異範圍。實測
      （2026-09-27）在「抽取退化成吃整檔」的情境下，正常執行與變異測試**雙雙通過**：
      因為變異抹掉的是該字串在原始檔中的全部出現，抽取吃多少都一樣被抹光。
      「抹掉全部命中」這個手法的判別力本質上等於正常執行。

    抽取退化真正的防線是兩項**結構性**檢查，都在 `notice_of` 裡：
      1. `block_hits == len(blocks)`：某段抽不到就報錯（不靜默丟棄該段）；
      2. `OUTSIDE_*` needle：抽取結果不得含 NOTICE 之外的字串。
    本函式對這兩項做故障注入，確認它們會紅——防線自己要有防線。
    """
    print("哨兵驗證：對抽取邏輯注入故障，確認結構性檢查會紅")
    failures = []

    # (1) 區段失配 → 必須被 notice_of 的區段數檢查抓到。
    #     故障注入的方式是**改寫腳本原文的 here-doc / here-string 標記**（腳本重構時
    #     真正會發生的事），而非把 broken pattern 餵進 extract()——後者會繞過 notice_of，
    #     於是拿掉區段數檢查也照樣通過（實測發現，2026-09-27）。
    delimiter_edits = [
        ("sh", SH.read_text(encoding="utf-8"), '<<NOTICE\n', '<<EOF\n'),
        ("sh", SH.read_text(encoding="utf-8"), '<<THEIA\n', '<<THEIA_BLOCK\n'),
        ("ps1", PS1.read_text(encoding="utf-8"), '@"\nCyTrace ', '@"\nCyTraceX '),
        ("ps1", PS1.read_text(encoding="utf-8"), '$TheiaNotice = @"', '$TheiaNotice = @\''),
    ]
    for which, src, old_mark, new_mark in delimiter_edits:
        if old_mark not in src:
            failures.append(f"{which}：故障注入用的標記 {old_mark!r} 不在腳本裡，注入無效")
            continue
        _, problems = notice_of(src.replace(old_mark, new_mark, 1), which)
        if not problems:
            failures.append(
                f"{which}：here-doc 標記改為 {new_mark!r} 後該段抽不到，"
                f"卻沒有被回報——該段的 NOTICE 內容會靜默不受檢查"
            )

    # (2) 抽取過寬 → 必須被 OUTSIDE needle 抓到
    #     模擬第七輪的 bug 形態：pattern 從檔頭吃起
    over_wide_cases = [
        ("sh", [(r"^", r"\nNOTICE\n")], SH_INLINE, SH.read_text(encoding="utf-8"), OUTSIDE_SH),
        (
            "ps1",
            [(r"<#", r'\n"@ \| Out-File')],
            PS1_INLINE,
            PS1.read_text(encoding="utf-8"),
            OUTSIDE_PS1,
        ),
    ]
    for which, blocks, inline, src, outside in over_wide_cases:
        notice, _, _ = extract(src, blocks, inline)
        caught = [n for n in outside if n in notice]
        if not caught:
            failures.append(
                f"{which} 抽取過寬（{len(notice)} 字元）卻沒有任何 OUTSIDE needle 命中"
                f"——哨兵清單涵蓋不足，第七輪那種 bug 會再次靜默通過"
            )

    # (3) 抽取為空 → 必須被空值檢查抓到
    for which in ("sh", "ps1"):
        notice, problems = notice_of("（完全不含 NOTICE 的內容）", which)
        if not problems:
            failures.append(f"{which}：空抽取未被回報")

    if failures:
        print("✗ 哨兵無法擋住下列故障：")
        for f in failures:
            print(f"    - {f}")
        return 1
    print(
        f"✓ 哨兵驗證通過（{len(SH_BLOCKS) + len(PS1_BLOCKS)} 個區段失配、"
        f"2 個抽取過寬、2 個空抽取，全數被結構性檢查攔下）"
    )
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="打包腳本 NOTICE 對帳")
    ap.add_argument(
        "--verify-sentinels",
        action="store_true",
        help="對抽取邏輯注入故障，確認結構性檢查（區段數 / OUTSIDE needle / 空值）會紅",
    )
    args = ap.parse_args()

    sh_notice, ps1_notice, problems = load()

    if problems:
        print("✗ NOTICE 區段抽取不可信，檢查結論無效：")
        for p in problems:
            print(f"    - {p}")
        return 1

    if args.verify_sentinels:
        return verify_sentinels()

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
