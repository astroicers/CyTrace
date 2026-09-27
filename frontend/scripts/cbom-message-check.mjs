/**
 * 前端 CBOM 成因渲染的實地檢查（ADR-013 / i18n 雙語強制）。
 *
 * 為什麼是一支獨立 script 而不是單元測試：前端無測試框架，而為此引入 vitest
 * 會多一個要離線建置與審授權的依賴（供應鏈純淨 + 穩定優先）。本檔只用
 * 既有的 i18next 與 node，`make frontend-check` 與 CI 的 frontend job 呼叫它。
 *
 * 為什麼需要它：`frontend/src/cbom.ts` 是 `Catalog::render_cbom` 的第二份實作。
 * Rust 側的契約測試（crates/cytrace-i18n/tests/cbom_keys.rs）比對鍵清單與變數名規則，
 * 但**擋不到行為差異**。實際抓到的兩個差異就是本檔存在的理由（2026-09-27）：
 *
 *   1. 空細節時 TS 側直接 `t(key)`，於是 `{{target}}` 原樣印在報表上
 *      ——第六輪已修過一次的畫面在前端重現。
 *   2. 括號寫死成全角「（）」，於是 en-US 出現 `Engine error（/path）`。
 *      Rust 側既有測試剛好只測到走插值分支的鍵，兩邊都沒抓到。
 *
 * 跑法：node frontend/scripts/cbom-message-check.mjs
 * （放在 frontend/ 之下是因為 node 的 ESM 解析看**腳本自身位置**找 node_modules，
 *   i18next 住在 frontend/node_modules）
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import i18n from 'i18next'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '../..') // repo 根

const zh = JSON.parse(fs.readFileSync(path.join(ROOT, 'locales/zh-TW.json'), 'utf8'))
const en = JSON.parse(fs.readFileSync(path.join(ROOT, 'locales/en-US.json'), 'utf8'))

// 鍵清單與變數名規則一律從實作檔讀出，不在此複製一份——
// 複製就等於再開一個會漂開的地方。
const SRC = fs.readFileSync(path.join(ROOT, 'frontend/src/cbom.ts'), 'utf8')
const KEYS = [...SRC.matchAll(/'(cbom\.err\.[a-z_]+)'/g)]
  .map((m) => m[1])
  .filter((k, i, a) => a.indexOf(k) === i)

if (KEYS.length === 0) {
  console.error('✗ 從 frontend/src/cbom.ts 抽不到任何鍵——檔案形式已變，檢查會空轉')
  process.exit(1)
}

const SENTINEL = '\u0000CYTRACE_PROBE\u0000'
const varFor = (k) => (k === 'cbom.err.timeout' ? 'secs' : 'target')

/** 與 frontend/src/cbom.ts 的 renderCbomFailure 同一條規則。 */
function render(t, key, detail, lang) {
  const k = KEYS.includes(key) ? key : 'cbom.err.engine'
  const v = varFor(k)
  const d = detail?.trim()
  if (!d) return t(k, { [v]: '?' })
  if (t(k, { [v]: SENTINEL }).includes(SENTINEL)) return t(k, { [v]: d })
  const isEn = (lang ?? 'zh-TW').toLowerCase().startsWith('en')
  const [o, c] = isEn ? [' (', ')'] : ['（', '）']
  return `${t(k)}${o}${d}${c}`
}

// CJK 統一漢字 + 全角標點：en-US 訊息一律不得出現
const FULLWIDTH = /[　-〿＀-￯一-鿿]/

await i18n.init({
  resources: { 'zh-TW': { translation: zh }, 'en-US': { translation: en } },
  lng: 'zh-TW',
  fallbackLng: 'zh-TW',
  interpolation: { escapeValue: false },
})

const problems = []
let checked = 0

for (const lng of ['zh-TW', 'en-US']) {
  await i18n.changeLanguage(lng)
  const t = i18n.t.bind(i18n)

  for (const key of KEYS) {
    const detail = key === 'cbom.err.timeout' ? '600' : '/mnt/target/firmware.bin'
    const out = render(t, key, detail, lng)
    checked++
    if (out.includes('{{')) problems.push(`${lng} ${key}: 殘留佔位符 → ${out}`)
    if (!out.includes(detail)) problems.push(`${lng} ${key}: 細節消失 → ${out}`)
    if (out.split(detail).length - 1 > 1) problems.push(`${lng} ${key}: 細節重複 → ${out}`)
    if (lng === 'en-US' && FULLWIDTH.test(out))
      problems.push(`${lng} ${key}: 夾全角字元 → ${out}`)
    if (out.trim() === key) problems.push(`${lng} ${key}: 渲染出裸鍵 → ${out}`)
  }

  // 邊界：空細節（`cbom_target("")` 可達）與未知鍵（schema 前進 / 手改 JSON）
  const empty = render(t, 'cbom.err.target_not_archive', '', lng)
  checked++
  if (empty.includes('{{')) problems.push(`${lng} 空細節殘留佔位符 → ${empty}`)

  const unknown = render(t, 'cbom.err.some_new_key_from_the_future', '/x', lng)
  checked++
  if (unknown.includes('cbom.err')) problems.push(`${lng} 未知鍵漏出裸鍵 → ${unknown}`)
  if (!unknown.includes('/x')) problems.push(`${lng} 未知鍵丟掉細節 → ${unknown}`)
}

if (problems.length > 0) {
  console.error('✗ CBOM 成因渲染有問題（報表會把這些字面印給交件對象看）：')
  for (const p of problems) console.error(`    - ${p}`)
  process.exit(1)
}

console.log(
  `✓ CBOM 成因渲染檢查通過（${KEYS.length} 鍵 × 2 語系 + 邊界，共 ${checked} 個案例；` +
    `無佔位符殘留、無細節丟失/重複、en-US 無全角、未知鍵不漏裸鍵）`,
)
