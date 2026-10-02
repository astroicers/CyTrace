/**
 * 前端 CBOM 成因渲染的實地檢查（ADR-013 / i18n 雙語強制）。
 *
 * **本檔 import 真正的 `renderCbomFailure`，不複製它的邏輯。**
 * 初版手抄了一份 `render()` 與 `varFor()`，於是它唯一擋得住的是它自己被改壞：
 * 實測（2026-09-27）把 `src/cbom.ts` 的空細節分支改回 `t(key)`、把括號改回寫死全角
 * ——它宣稱擋住的那兩個缺陷——腳本**兩次都是綠的（exit 0）**。
 * 那正是第七輪 blocker「gate 擋不到它宣稱擋的東西」的同型重演，而且更糟：
 * 它讓漂移面從「Rust + TS」兩份變成三份（第八輪複審 finding A）。
 *
 * 為什麼不用測試框架：Node 22 的型別剝離（`--experimental-strip-types`）能直接 import
 * `.ts`，零新增依賴即可驗真實作。引入 vitest 會多一個要離線建置與審授權的相依
 * （供應鏈純淨 + 穩定優先）。
 *
 * 為什麼需要它：`frontend/src/cbom.ts` 是 `Catalog::render_cbom` 的第二份實作
 * （報表有執行期語言切換器，不能在 Rust 端預渲染成固定字串）。Rust 側的契約測試
 * （crates/cytrace-i18n/tests/cbom_keys.rs）比對鍵清單與變數名規則，**擋不到行為差異**。
 *
 * 跑法：node --experimental-strip-types frontend/scripts/cbom-message-check.mts
 * （放在 frontend/ 之下是因為 node 的 ESM 解析看**腳本自身位置**找 node_modules，
 *   i18next 住在 frontend/node_modules）
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import i18n from 'i18next'
import type { TFunction } from 'i18next'
// ← 真實作。改壞它，本檔必須轉紅；這行是整支檢查的意義所在。
import { CBOM_ERROR_KEYS, SECS_KEYS, renderCbomFailure } from '../src/cbom.ts'
// console 的錯誤顯示分工。這頁沒有 render 層測試，而「訊息」與「detail 要不要再印」
// 在兩處各判一次必然會不同步（第十輪複審：detail 印了兩次）。
import { describeJobError } from '../src/console/jobError.ts'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '../..') // repo 根

const zh = JSON.parse(fs.readFileSync(path.join(ROOT, 'locales/zh-TW.json'), 'utf8'))
const en = JSON.parse(fs.readFileSync(path.join(ROOT, 'locales/en-US.json'), 'utf8'))

// CJK 統一漢字 + 全角標點：en-US 訊息一律不得出現
const FULLWIDTH = /[　-〿＀-￯一-鿿]/

await i18n.init({
  resources: { 'zh-TW': { translation: zh }, 'en-US': { translation: en } },
  lng: 'zh-TW',
  fallbackLng: 'zh-TW',
  interpolation: { escapeValue: false },
})

/**
 * `job_error_of`（crates/cytrace-server/src/jobs/runner.rs）實際會產出的 `server.err.*`。
 * 手挑幾個鍵的話，替 `server.err.*` 文案加佔位符不會被任何檢查擋到
 * ——`every_message_uses_...` 只涵蓋 `cbom.err.*`（第十一輪複審 finding H）。
 */
const SERVER_ERR_KINDS = ['engine', 'parse', 'io', 'config', 'db_missing'] as const

const CONSOLE_CASES: Array<{ label: string; i18n_key: string; detail?: string | null }> = [
  { label: 'CBOM 成因', i18n_key: 'cbom.err.timeout', detail: '600' },
  { label: 'CBOM 無細節', i18n_key: 'cbom.err.empty_output', detail: null },
  ...SERVER_ERR_KINDS.map((k) => ({
    label: `server.err.${k}`,
    i18n_key: `server.err.${k}`,
    detail: 'exit 2: boom',
  })),
  { label: '查不到的鍵', i18n_key: 'server.err.no_such_key', detail: '/var/lib/x' },
  { label: '空鍵 + 有細節', i18n_key: '', detail: '/var/lib/x' },
  { label: '空鍵 + 無細節', i18n_key: '', detail: null },
]

const problems: string[] = []
let checked = 0
let consoleChecked = 0

// SECS_KEYS 為空時 `SECS_KEYS[0]` 是 undefined，「undefined 細節」那個邊界案
// 會改去驗 cbom.err.engine 而仍然綠——判別力流失（第十一輪複審 finding J）。
if (SECS_KEYS.length === 0) {
  console.error('✗ SECS_KEYS 為空——以秒數為細節的邊界案會在空轉')
  process.exit(1)
}

function check(label: string, out: string, expect: { detail?: string; lng: string }) {
  checked++
  const { detail, lng } = expect
  if (out.includes('{{')) problems.push(`${label}: 殘留佔位符 → ${out}`)
  if (out.trim().startsWith('cbom.err.')) problems.push(`${label}: 渲染出裸鍵 → ${out}`)
  if (lng === 'en-US' && FULLWIDTH.test(out)) problems.push(`${label}: 夾全角字元 → ${out}`)
  // 反方向同樣要釘：zh-TW 的附加括號必須是全角，否則中文訊息裡混半角括號。
  // 原本只檢查 en-US，等於字形規則只有一半被守住（第九輪複審）。
  if (lng === 'zh-TW' && / \(.+\)$/.test(out))
    problems.push(`${label}: zh-TW 應用全角括號「（）」→ ${out}`)
  if (detail) {
    if (!out.includes(detail)) problems.push(`${label}: 細節消失 → ${out}`)
    else if (out.split(detail).length - 1 > 1) problems.push(`${label}: 細節重複 → ${out}`)
  }
}

for (const lng of ['zh-TW', 'en-US']) {
  await i18n.changeLanguage(lng)
  const t = i18n.t.bind(i18n) as TFunction

  for (const key of CBOM_ERROR_KEYS) {
    // 細節形態依**事實源**決定，不在此重寫規則。
    // 這一行原本是 `key === 'cbom.err.timeout' ? ...`——正是 src/cbom.ts 與
    // Catalog::render_cbom 兩處註解都指名為「第八輪犯的錯」的那個單一比較，
    // 在本腳本裡隔 30 行原封不動存活（第十輪複審 finding 1）。
    // 後果：drain_timeout 拿到路徑當秒數，渲染成「引擎輸出抽取逾時 /mnt/… 秒」，
    // 而 check() 的四條判定全數通過——這支腳本的存在理由就是不複製邏輯，它卻複製了。
    const detail = SECS_KEYS.includes(key) ? '600' : '/mnt/target/firmware.bin'
    check(`${lng} ${key}`, renderCbomFailure(t, key, detail, lng), { detail, lng })
  }

  // 邊界 1：空細節（`cbom_target("")` 可達）——不得留下未插值的佔位符
  check(`${lng} 空細節`, renderCbomFailure(t, 'cbom.err.target_not_archive', '', lng), { lng })

  // 邊界 2：detail 為 null / undefined（`reason_detail` 在序列化時可省略）
  check(`${lng} null 細節`, renderCbomFailure(t, 'cbom.err.target_not_archive', null, lng), {
    lng,
  })
  check(`${lng} undefined 細節`, renderCbomFailure(t, SECS_KEYS[0], undefined, lng), {
    lng,
  })

  // 邊界 3：未知鍵（schema 前進、或手改過的 JSON）——不得把裸鍵印給交件對象看
  const future = renderCbomFailure(t, 'cbom.err.some_new_key_from_the_future', '/x', lng)
  check(`${lng} 未知鍵`, future, { detail: '/x', lng })

  // 邊界 4：reasonKey 本身缺漏
  check(`${lng} 無鍵`, renderCbomFailure(t, undefined, '/x', lng), { detail: '/x', lng })

  // 邊界 5：未傳語系（App 之外的呼叫端可能漏傳）——不得因此吐出佔位符或裸鍵
  check(`${lng} 未傳語系`, renderCbomFailure(t, 'cbom.err.engine', '/x'), {
    detail: '/x',
    lng: 'zh-TW', // 未傳時的預期行為是退回 zh-TW 字形，故不套 en-US 的全角檢查
  })
}

// ── console 的 job 錯誤顯示：訊息與 detail 不得重覆 ──
//
// 與報表同一條不變量（CLI 側斷言「細節不得重複出現」），只是位置在 console。
for (const lng of ['zh-TW', 'en-US']) {
  await i18n.changeLanguage(lng)
  const t = i18n.t.bind(i18n) as TFunction
  for (const c of CONSOLE_CASES) {
    checked++
    consoleChecked++
    const { text, detailConsumed } = describeJobError(c, t, lng)
    const label = `${lng} console ${c.label}`
    if (!text) problems.push(`${label}: 訊息為空——操作員看不到任何成因`)
    if (text.includes('{{')) problems.push(`${label}: 殘留佔位符 → ${text}`)
    // 裸鍵判定不列命名空間白名單：第三個命名空間出現時會靜默逃逸
    // （第十一輪複審 finding I）。改以「顯示文字就是那個鍵」與 i18n 鍵形態判定。
    if (text === c.i18n_key && c.i18n_key !== '')
      problems.push(`${label}: 顯示裸鍵（文字等於 i18n_key）→ ${text}`)
    if (/^[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}$/.test(text.trim()))
      problems.push(`${label}: 顯示疑似裸 i18n 鍵 → ${text}`)
    // detail 被訊息用掉時，<pre> 不得再印一次
    if (c.detail && detailConsumed && !text.includes(c.detail))
      problems.push(`${label}: 宣告 detail 已用掉，但訊息裡沒有它 → ${text}`)
    if (c.detail && !detailConsumed && text.includes(c.detail))
      problems.push(
        `${label}: 訊息已含 detail 卻未宣告用掉——<pre> 會再印一次 → ${text}`,
      )
  }
}

// ── job 錯誤的退回鏈：與 server 的 render_job_error 共用同一份 fixture，兩邊各自驗 ──
// 前版只在註解宣稱兩邊「規則相同」，實際上查不到鍵時 console 退回 detail、server 退回
// kind 泛用句（第三輪複審 server#5）。server 側：tests/jobs.rs 的
// job_error_message_follows_shared_fallback_fixture。
const FX = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'crates/cytrace-server/tests/fixtures/job-error-render.json'), 'utf8'),
) as { cases: Array<{ name: string; error: { kind: string; i18n_key: string; detail: string }; expect: { key?: string; detail?: boolean } }> }
let fxChecked = 0
for (const lng of ['zh-TW', 'en-US']) {
  await i18n.changeLanguage(lng)
  const t = i18n.t.bind(i18n) as TFunction
  for (const c of FX.cases) {
    const { text, detailConsumed } = describeJobError(c.error, t, lng)
    const want = c.expect.key ? t(c.expect.key) : c.error.detail
    const wantConsumed = !c.expect.key
    if (!want || want === c.expect.key) problems.push(`fixture「${c.name}」: 預期文字無效（鍵查不到？）`)
    if (text !== want || detailConsumed !== wantConsumed) {
      problems.push(
        `${lng} fixture「${c.name}」: 得「${text}」(detail 用掉=${detailConsumed})，應為「${want}」(${wantConsumed})`,
      )
    }
    fxChecked++
  }
}
if (FX.cases.length < 5 || fxChecked !== FX.cases.length * 2) {
  problems.push(`job 錯誤 fixture 只驗了 ${fxChecked} 個案例——fixture 或迴圈可能失效`)
}

// 反空轉：import 成功但清單為空、或某個迴圈沒跑到，`problems` 也會是空的而看似通過。
//
// **下限由組成推導且分段**：初版寫死 `MIN_CASES = 30`，而報表側恰好就是 30
// （9 鍵 + 6 邊界）× 2 語系 = 30，於是整個 console 段對這個哨兵的貢獻是零——
// 把 console 迴圈整段刪掉，`checked` 仍是 30、`30 < 30` 為 false、仍然 exit 0。
// 本輪唯一為新機制加的反空轉下限，恰好保護不到那個新機制（第十一輪複審 finding A，
// 實測確認：刪掉 console 迴圈後 exit 0）。
const LANGS = 2
const REPORT_MIN = (CBOM_ERROR_KEYS.length + 6) * LANGS
const CONSOLE_MIN = CONSOLE_CASES.length * LANGS
const reportChecked = checked - consoleChecked
if (reportChecked < REPORT_MIN) {
  console.error(
    `✗ 報表側只跑了 ${reportChecked} 個案例（應 ≥ ${REPORT_MIN}）——` +
      `鍵清單或迴圈可能失效，此時「檢查通過」這個結論不含資訊`,
  )
  process.exit(1)
}
if (consoleChecked < CONSOLE_MIN) {
  console.error(
    `✗ console 側只跑了 ${consoleChecked} 個案例（應 ≥ ${CONSOLE_MIN}）——` +
      `顯示分工的檢查可能已失效`,
  )
  process.exit(1)
}

if (problems.length > 0) {
  console.error('✗ CBOM 成因渲染有問題（報表會把這些字面印給交件對象看）：')
  for (const p of problems) console.error(`    - ${p}`)
  process.exit(1)
}

console.log(
  `✓ CBOM 成因渲染檢查通過（${CBOM_ERROR_KEYS.length} 鍵 × 2 語系 + 5 類邊界，共 ${checked} 個案例；` +
    `驗的是 src/cbom.ts 的 renderCbomFailure 本身，非副本；job 錯誤退回鏈 ${fxChecked} 例與 server 共用 fixture）`,
)
