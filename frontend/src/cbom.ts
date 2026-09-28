// CBOM 失敗成因的渲染（ADR-013 決策 4）。
//
// 為什麼這份邏輯在前端而不在 Rust：報表是**單檔 HTML 且有執行期語言切換器**，
// 若在產生報表時就把訊息渲染成固定字串，切語言時它不會跟著變——那是 i18n 雙語
// 強制鐵則的實質違反。故 Rust 只寫入純鍵 + 不可翻譯細節（`reason_key` /
// `reason_detail`），由此處依當前語系渲染。
//
// 這使它成為 `Catalog::render_cbom`（crates/cytrace-i18n/src/lib.rs）的第二份實作，
// 也就是「兩邊各寫一份，就會有一邊先退化」的風險。承接方式是一支跨語言契約測試
// （crates/cytrace-i18n/tests/cbom_keys.rs）讀本檔並比對鍵集合：任一側加鍵而另一側
// 沒加就轉紅。規則本身刻意保持極小，就是為了讓兩份不容易漂開。

import type { TFunction } from 'i18next'

/**
 * Rust `CytraceError::Cbom` 可能產生的全部 i18n 鍵。
 *
 * 以**字面鍵陣列**列出而非動態 `t(reason_key)`：`scripts/i18n-check.py` 的反向檢查
 * 只看得到字面鍵，動態組鍵會讓這 8 個鍵在前端側完全沒有覆蓋。
 */
export const CBOM_ERROR_KEYS = [
  'cbom.err.target_not_local',
  'cbom.err.target_unreadable',
  'cbom.err.target_not_archive',
  'cbom.err.timeout',
  'cbom.err.drain_timeout',
  'cbom.err.empty_output',
  'cbom.err.stdout_not_json',
  'cbom.err.not_cyclonedx',
  'cbom.err.engine',
] as const

export type CbomErrorKey = (typeof CBOM_ERROR_KEYS)[number]

/**
 * 鍵 → 細節的變數名。與 Rust `Catalog::var_for_cbom_key` 同一份明表。
 *
 * 原本寫成 `key === 'cbom.err.timeout' ? 'secs' : 'target'`。第八輪新增
 * `cbom.err.drain_timeout`（文案用 `{{secs}}`）時，它落到 else 分支拿到 `target`，
 * 於是插值不發生、`{{secs}}` 原樣印在畫面上——第六輪已修過一次的同一個畫面
 * （第九輪複審）。**以秒數為細節的鍵不只一個**，故列成明表而非單一比較；
 * 新增鍵時 `every_message_uses_the_placeholder_its_rule_assigns` 會當場攔住不一致。
 */
export const SECS_KEYS: readonly string[] = [
  'cbom.err.timeout',
  'cbom.err.drain_timeout',
]

function varNameFor(key: string): 'secs' | 'target' {
  return SECS_KEYS.includes(key) ? 'secs' : 'target'
}

/**
 * 把 `reason_key` + `reason_detail` 渲染成當前語系的成因文字。
 *
 * 三條規則與 Rust `Catalog::render_cbom` 一致：
 * 1. 無細節 → 直接取譯文。
 * 2. 譯文含該變數的佔位符 → 插值。
 * 3. 譯文**沒有**該變數的位置 → 細節補在括號內（不讓它消失）。
 *
 * 判準是「譯文原文是否含佔位符」，不是事後檢查細節有沒有出現在結果裡：
 * 後者在細節恰為譯文子字串時會靜默丟棄細節（Rust 側第七輪複審的同一個 finding）。
 * 未知的鍵一律回退 `cbom.err.engine`——報表不得印出裸鍵給交件對象看。
 */
export function renderCbomFailure(
  t: TFunction,
  reasonKey: string | undefined,
  reasonDetail: string | null | undefined,
  lang?: string,
): string {
  const key = (CBOM_ERROR_KEYS as readonly string[]).includes(reasonKey ?? '')
    ? (reasonKey as CbomErrorKey)
    : 'cbom.err.engine'

  const varName = varNameFor(key)
  const detail = reasonDetail?.trim()

  // 空細節仍須插值，否則文案裡的 {{target}} 會原樣印在報表上
  // ——那正是第六輪已修過一次的畫面（node 實測抓到 TS 側重現了它）。
  if (!detail) return t(key, { [varName]: '?' })

  // i18next 的 t() 回傳的是已插值的字串，故以哨兵值探測「原文是否含該佔位符」：
  // 傳一個不會出現在任何文案裡的值，看它有沒有被放進結果。
  const SENTINEL = '\u0000CYTRACE_PROBE\u0000'
  if (t(key, { [varName]: SENTINEL }).includes(SENTINEL)) {
    return t(key, { [varName]: detail })
  }
  // 文案沒有該變數的位置 → 補在括號內。**括號依語系**：寫死全角會讓 en-US
  // 訊息夾全角標點（與 Rust `Catalog::parens` 同一條規則）。
  const isEn = (lang ?? 'zh-TW').toLowerCase().startsWith('en')
  const [open, close] = isEn ? [' (', ')'] : ['（', '）']
  return `${t(key)}${open}${detail}${close}`
}
