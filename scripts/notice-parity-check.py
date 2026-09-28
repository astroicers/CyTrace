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

# 每一列的適用範圍：NOTICE 的內容依「包內是否含 theia」而不同，故不是每一列都在兩種
# 產出裡都該出現。原本把兩種組合的聯集當成一份來驗，於是條件段裡的聲明在
# WITHOUT_CBOM 的包中缺席也驗不出來（第九輪複審 finding 5）。
ALWAYS = "always"
THEIA_ONLY = "theia"
NO_THEIA_ONLY = "no-theia"

# 每一項：(說明, sh 需含的 pattern, ps1 需含的 pattern, 適用範圍)
# 分列兩欄是因為兩份 NOTICE 一中一英；共用的專有名詞才寫同一字串。
REQUIRED = [
    ("Syft 授權", r"Syft", r"Syft", ALWAYS),
    ("Grype 授權", r"Grype", r"Grype", ALWAYS),
    # 下列三列**只在含 theia 的包**中出現（條件段），故 WITHOUT_CBOM 組合不檢查它們
    ("theia 授權（條件段）", r"CBOMkit-theia", r"CBOMkit-theia", THEIA_ONLY),
    ("theia 相依 MPL-2.0 標示", r"MPL-2\.0", r"MPL-2\.0", THEIA_ONLY),
    ("theia 相依 gitleaks MIT 標示", r"gitleaks", r"gitleaks", THEIA_ONLY),
    # 這一列反過來：**只在不含 theia 的包**中出現
    ("theia 缺席時的明示降級", r"不含 CBOM 引擎", r"does not include the CBOM engine", NO_THEIA_ONLY),
    ("ring 混合授權（ISC + OpenSSL/BoringSSL）", r"\bring\b", r"\bring\b", ALWAYS),
    ("ring 的 OpenSSL/BoringSSL 條款", r"OpenSSL/BoringSSL", r"OpenSSL/BoringSSL", ALWAYS),
    ("rustls（TLS 提供者）", r"rustls", r"rustls", ALWAYS),
    ("自產 SBOM 交叉引用", r"cytrace\.sbom\.cdx\.json", r"cytrace\.sbom\.cdx\.json", ALWAYS),
    ("禁中國來源宣告", r"OpenSCA-cli", r"OpenSCA-cli", ALWAYS),
    ("該宣告的涵蓋範圍註記", r"國籍", r"does not cover the nationality", ALWAYS),
    ("cargo-deny 把關聲明", r"cargo-deny", r"cargo-deny", ALWAYS),
    # Apache-2.0 §4(b) 對「是否修改過原始碼」有聲明要求；sh 有、ps1 原本整句缺
    # （第八輪複審 finding I）
    ("未修改原始碼之聲明", r"未修改原始碼", r"source was not modified", ALWAYS),
    ("上游 vendor 目錄指引", r"vendor 目錄", r"vendor directory", ALWAYS),
]

# NOTICE 區段的界線。兩支腳本都是「條件段（theia）」＋「主體」兩塊，
# 條件段的 else 分支是單行賦值，故一併以賦值列的字串內容納入。
SH_BLOCKS = [
    # THEIA_NOTICE="$(cat <<THEIA … THEIA )"
    (r'THEIA_NOTICE="\$\(cat <<THEIA\n', r"\nTHEIA\n"),
    # cat > "$BUNDLE/NOTICE" <<NOTICE … NOTICE
    (r'cat > "\$BUNDLE/NOTICE" <<NOTICE\n', r"\nNOTICE\n"),
]
# `[^"\n]*` 而非 `[^"]*`：後者會跨行，於是 here-doc 的開頭那行
# （`THEIA_NOTICE="$(cat <<THEIA`）也被吃進來、一路吃到下一個引號。
# 後果是 inline_hits 永遠 ≥ 1，inline 檢查形同失效，且 here-doc 內容被重複計入
# （由 --verify-sentinels 的 inline 注入當場抓到，第九輪修 finding 3/4 時發現）。
SH_INLINE = r'^\s*THEIA_NOTICE="([^"\n]*)"\s*$'

PS1_BLOCKS = [
    # $TheiaNotice = @" … "@
    (r'\$TheiaNotice = @"\n', r'\n"@\n'),
    # @" … "@ | Out-File … NOTICE
    (r'@"\nCyTrace ', r'\n"@ \| Out-File'),
]
# ps1 側**刻意**允許 `"`（與 SH_INLINE 的 `[^"\n]*` 不同）：`package.ps1` 的該行
# 以 `` `" `` 跳脫引號，收窄成 `[^"\n]*` 會讓它抽不到。這個不對稱是必要的，別順手統一。
# （收窄為 `[^\n]*` 對 ps1 其實是 no-op：extract 用 re.M 而非 re.S，`.` 本就不跨行。）
PS1_INLINE = r"^\s*\$TheiaNotice = \"([^\n]*)\"\s*$"


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


def combos_of(src: str, which: str) -> tuple[dict[str, str], list[str]]:
    """把腳本原文拆成兩種**實際會出貨的 NOTICE 組合**，並回報重建本身的問題。

    NOTICE 的內容依「包內是否含 theia」而不同：含 theia 走 here-doc 條件段，
    不含則走單行的降級說明。把兩者併成一個 blob 來驗，「條件段裡的聲明在
    WITHOUT_CBOM 的包中缺席」就驗不出來（第九輪複審 finding 5）。

    **吃傳入的 `src`，不自己讀檔**：初版簽章收 `notice` 卻完全不用、改讀
    `SH.read_text()`，於是 `load()` 抽出來的東西不是 `check()` 驗的東西，
    而故障注入改寫過的原文也到不了這裡（第十輪複審 finding 5）。

    **重建失效要回報**：任一區段抓不到就回空字串的話，該組合會少料而看起來只是
    「缺某一列」，讀者無從分辨是聲明真的缺、還是重建壞了（同輪 finding 4）。
    """
    if which == "sh":
        blocks, inline_pat, name = SH_BLOCKS, SH_INLINE, "package.sh"
    else:
        blocks, inline_pat, name = PS1_BLOCKS, PS1_INLINE, "package.ps1"

    problems = []
    theia_block = re.search(blocks[0][0] + r"(.*?)" + blocks[0][1], src, re.S)
    body = re.search(blocks[1][0] + r"(.*?)" + blocks[1][1], src, re.S)
    # inline 取全部命中，與 extract() 的 finditer 對齊（初版用 re.search 只取第一個）
    inlines = [m.group(1) for m in re.finditer(inline_pat, src, re.M)]

    if theia_block is None:
        problems.append(f"{name}：{MARK_COMBO} 抓不到 theia 條件段")
    if body is None:
        problems.append(f"{name}：{MARK_COMBO} 抓不到 NOTICE 主體")
    if not inlines:
        problems.append(f"{name}：{MARK_COMBO} 抓不到 theia 缺席時的單行說明")

    b = body.group(1) if body else ""
    return (
        {
            THEIA_ONLY: b + "\n" + (theia_block.group(1) if theia_block else ""),
            NO_THEIA_ONLY: b + "\n" + "\n".join(inlines),
        },
        problems,
    )


def check() -> list[str]:
    """回傳缺漏清單（空清單 = 通過）。

    對**兩種實際產出組合**各驗一次，而非驗兩者的聯集。
    """
    missing = []
    sh_combos, sh_problems = combos_of(SH.read_text(encoding="utf-8"), "sh")
    ps1_combos, ps1_problems = combos_of(PS1.read_text(encoding="utf-8"), "ps1")
    missing.extend(sh_problems)
    missing.extend(ps1_problems)
    for label, sh_pat, ps1_pat, scope in REQUIRED:
        for combo in (THEIA_ONLY, NO_THEIA_ONLY):
            if scope not in (ALWAYS, combo):
                continue
            desc = "含 theia 的包" if combo == THEIA_ONLY else "不含 theia 的包"
            if not re.search(sh_pat, sh_combos[combo]):
                missing.append(f"package.sh（{desc}）的 NOTICE 缺「{label}」")
            if not re.search(ps1_pat, ps1_combos[combo]):
                missing.append(f"package.ps1（{desc}）的 NOTICE 缺「{label}」")
    return missing


# 三個結構性檢查的特徵字串。故障注入必須斷言「回報的是這一條」，
# 而非「有任何問題被回報」——後者會讓三組注入互相頂替，任一組都證不出自己那個檢查存在
# （第九輪複審 finding 3、4：實測刪掉 OUTSIDE 迴圈或空值檢查，哨兵驗證仍為 exit 0）。
MARK_SECTION_COUNT = "只抽到"
MARK_OVER_WIDE = "抽取範圍過寬"
MARK_EMPTY = "抽取為空"
MARK_INLINE = "單行 NOTICE 抽不到"
MARK_COMBO = "產出組合重建失效"


def notice_of(
    text: str, which: str, blocks=None, inline: str | None = None
) -> tuple[str, list[str]]:
    """從腳本原文抽出 NOTICE 區段，並回報抽取本身的問題。

    `blocks` / `inline` 開放注入只為故障測試（`--verify-sentinels`）：不開放的話，
    「抽取過寬」這種故障無法經由本函式製造，驗證只能自己複製一份包含判定
    ——那就是第八輪 finding A 的錯法（驗自己的副本）。
    """
    if which == "sh":
        d_blocks, d_inline, outside = SH_BLOCKS, SH_INLINE, OUTSIDE_SH
    else:
        d_blocks, d_inline, outside = PS1_BLOCKS, PS1_INLINE, OUTSIDE_PS1
    blocks = d_blocks if blocks is None else blocks
    inline = d_inline if inline is None else inline
    notice, block_hits, inline_hits = extract(text, blocks, inline)
    problems = []
    name = "package.sh" if which == "sh" else "package.ps1"
    if block_hits != len(blocks):
        problems.append(
            f"{name}：{len(blocks)} 個 NOTICE 區段{MARK_SECTION_COUNT} {block_hits} 個"
            f"——here-doc / here-string 形式可能已改變，該段內容不會被檢查"
        )
    if inline_hits < 1:
        problems.append(f"{name}：theia 缺席時的{MARK_INLINE}")
    if not notice.strip():
        problems.append(f"{name}：NOTICE 區段{MARK_EMPTY}")
    for needle in outside:
        if needle in notice:
            problems.append(f"{name} {MARK_OVER_WIDE}：含 NOTICE 之外的 {needle!r}")
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

    誠實記錄三個版本的失敗，因為它們是同一種錯法的三次變形：

    - 第一版變異**抽取後的字串**。`re.sub` 移除 pattern 的全部命中後，隨後的 `re.search`
      依構造必然失敗，故「抹去後仍通過」永不觸發；而「pattern 無命中」早已被正常執行
      蘊含。通過條件 ≡ 正常執行的通過條件（第八輪複審 finding C）。
    - 第二版把變異上移到**打包腳本原文**，以為能把 `extract()` 納入範圍。實測在
      「抽取退化成吃整檔」的情境下，正常執行與變異測試**雙雙通過**：變異抹掉的是該字串
      在原始檔中的全部出現，抽取吃多少都一樣被抹光。
    - 第三版（本函式的前身）改為對結構性檢查注入故障，方向對了，但三組注入只斷言
      「有任何問題被回報」。實測（第九輪複審 finding 3、4）：刪掉 OUTSIDE 迴圈或空值檢查，
      哨兵驗證**仍為 exit 0**——因為同一個輸入會同時觸發別的檢查，三組互相頂替。
      而第 2 組還自己複製了一份包含判定（`n in notice`），驗的是副本。

    本版每組注入都：(a) 經 `notice_of` 製造故障，不自己複製判定；
    (b) 斷言回報訊息**含該檢查的特徵字串**，於是每個檢查各自有一條會紅的哨兵。
    """
    print("哨兵驗證：對抽取邏輯注入故障，確認每個結構性檢查各自會紅")
    failures = []
    sh_src = SH.read_text(encoding="utf-8")
    ps1_src = PS1.read_text(encoding="utf-8")

    def expect(label: str, problems: list[str], mark: str) -> None:
        if not any(mark in p for p in problems):
            failures.append(
                f"{label}：預期回報含「{mark}」的問題，實得 {problems or '（無問題）'}"
                f"——該檢查可能已被拿掉，而此注入靠別的檢查頂替"
            )

    # (1) 區段失配 → 區段數檢查。改寫腳本原文的 here-doc / here-string 標記
    #     （腳本重構時真正會發生的事），而非把 broken pattern 餵進 extract()。
    delimiter_edits = [
        ("sh", sh_src, "<<NOTICE\n", "<<EOF\n"),
        ("sh", sh_src, "<<THEIA\n", "<<THEIA_BLOCK\n"),
        ("ps1", ps1_src, '@"\nCyTrace ', '@"\nCyTraceX '),
        ("ps1", ps1_src, '$TheiaNotice = @"', "$TheiaNotice = @'"),
    ]
    for which, src, old_mark, new_mark in delimiter_edits:
        if old_mark not in src:
            failures.append(f"{which}：注入用的標記 {old_mark!r} 不在腳本裡，注入無效")
            continue
        _, problems = notice_of(src.replace(old_mark, new_mark, 1), which)
        expect(f"{which} 區段標記改為 {new_mark!r}", problems, MARK_SECTION_COUNT)

    # (2) 抽取過寬 → OUTSIDE needle 檢查。**經 notice_of 注入 blocks**，
    #     不自己複製包含判定（第八輪 finding A 的錯法）。
    over_wide = [
        ("sh", sh_src, [(r"^", r"\nNOTICE\n")]),
        ("ps1", ps1_src, [(r"<#", r'\n"@ \| Out-File')]),
    ]
    for which, src, blocks in over_wide:
        _, problems = notice_of(src, which, blocks=blocks)
        expect(f"{which} 抽取過寬", problems, MARK_OVER_WIDE)

    # (3) 抽取為空 → 空值檢查。需要一個**只**觸發它的輸入：兩個 block 都命中、
    #     inline 也命中，但捕獲組為空。故合成一份「標記齊全而內容為空」的腳本。
    empty_sh = (
        'THEIA_NOTICE="$(cat <<THEIA\n\nTHEIA\n)"\n'
        'THEIA_NOTICE=""\n'
        'cat > "$BUNDLE/NOTICE" <<NOTICE\n\nNOTICE\n'
    )
    _, problems = notice_of(empty_sh, "sh")
    expect("sh 標記齊全但內容為空", problems, MARK_EMPTY)
    if any(MARK_SECTION_COUNT in p for p in problems):
        failures.append(
            "sh 空內容注入同時觸發了區段數檢查——此注入不再單獨對到空值檢查，"
            "無法證明後者存在"
        )

    # (4) inline 抽不到 → inline 檢查（原本沒有任何注入單獨對到它）
    no_inline_sh = sh_src.replace('THEIA_NOTICE="  （本包不含 CBOM 引擎', 'X_NOTICE="  （本包不含 CBOM 引擎', 1)
    if no_inline_sh == sh_src:
        failures.append("sh：inline 注入用的賦值列不在腳本裡，注入無效")
    else:
        _, problems = notice_of(no_inline_sh, "sh")
        expect("sh 單行 NOTICE 賦值改名", problems, MARK_INLINE)

    # (5) 產出組合重建失效 → combos_of 的結構性檢查。
    #     `--verify-sentinels` 原本在 check() 之前 return，四組注入一次都沒經過
    #     combos_of 與 scope 欄——本輪唯一沒有哨兵的新機制（第十輪複審 finding 4）。
    for which, src, old_mark, new_mark, what in [
        ("sh", sh_src, "<<THEIA\n", "<<THEIA_X\n", "theia 條件段"),
        ("sh", sh_src, 'cat > "$BUNDLE/NOTICE" <<NOTICE', 'cat > "$BUNDLE/NOTICE" <<EOF', "NOTICE 主體"),
        ("ps1", ps1_src, '$TheiaNotice = @"', "$TheiaNotice = @'", "theia 條件段"),
    ]:
        if old_mark not in src:
            failures.append(f"{which}：組合注入用的標記 {old_mark!r} 不在腳本裡，注入無效")
            continue
        _, problems = combos_of(src.replace(old_mark, new_mark, 1), which)
        expect(f"{which} {what}抓不到", problems, MARK_COMBO)

    # (6) scope 欄有效：把「只屬於不含 theia 的包」那一列移進條件段，
    #     `check()` 必須指名是哪一種組合缺料。這條直接驗 REQUIRED 的 scope 語意，
    #     而非只驗 combos_of 的結構。
    moved = sh_src.replace(
        'THEIA_NOTICE="  （本包不含 CBOM 引擎',
        'THEIA_NOTICE_MOVED="  （本包不含 CBOM 引擎',
        1,
    )
    if moved == sh_src:
        failures.append("sh：scope 注入用的 inline 賦值不在腳本裡，注入無效")
    else:
        combos, _ = combos_of(moved, "sh")
        no_theia = combos[NO_THEIA_ONLY]
        hit = any(
            re.search(pat, no_theia)
            for label, pat, _, scope in REQUIRED
            if scope == NO_THEIA_ONLY
        )
        if hit:
            failures.append(
                "sh：移走「不含 CBOM 引擎」那行之後，NO_THEIA 組合裡仍命中該列"
                "——scope 欄或組合重建沒有把兩種產出分開"
            )

    if failures:
        print("✗ 哨兵無法擋住下列故障：")
        for f in failures:
            print(f"    - {f}")
        return 1
    print(
        "✓ 哨兵驗證通過（區段數 ×4、抽取過寬 ×2、空值 ×1、inline ×1、"
        "組合重建 ×3、scope 語意 ×1；每組各自斷言該檢查的特徵訊息，不靠別的檢查頂替）"
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

    missing = check()
    if missing:
        print("✗ 兩平台 NOTICE 不對稱——會出授權聲明不實的交付包：")
        for m in missing:
            print(f"    - {m}")
        return 1

    print(
        f"✓ NOTICE 對帳通過（{len(REQUIRED)} 項法律必要實體 × 2 平台 × "
        f"2 種產出組合（含/不含 theia）；比對範圍為 NOTICE 區段 "
        f"{len(sh_notice)} / {len(ps1_notice)} 字元）"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
