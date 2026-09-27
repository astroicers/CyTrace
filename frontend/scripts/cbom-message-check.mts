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
import { CBOM_ERROR_KEYS, renderCbomFailure } from '../src/cbom.ts'

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

const problems: string[] = []
let checked = 0

function check(label: string, out: string, expect: { detail?: string; lng: string }) {
  checked++
  const { detail, lng } = expect
  if (out.includes('{{')) problems.push(`${label}: 殘留佔位符 → ${out}`)
  if (out.trim().startsWith('cbom.err.')) problems.push(`${label}: 渲染出裸鍵 → ${out}`)
  if (lng === 'en-US' && FULLWIDTH.test(out)) problems.push(`${label}: 夾全角字元 → ${out}`)
  if (detail) {
    if (!out.includes(detail)) problems.push(`${label}: 細節消失 → ${out}`)
    else if (out.split(detail).length - 1 > 1) problems.push(`${label}: 細節重複 → ${out}`)
  }
}

for (const lng of ['zh-TW', 'en-US']) {
  await i18n.changeLanguage(lng)
  const t = i18n.t.bind(i18n) as TFunction

  for (const key of CBOM_ERROR_KEYS) {
    const detail = key === 'cbom.err.timeout' ? '600' : '/mnt/target/firmware.bin'
    check(`${lng} ${key}`, renderCbomFailure(t, key, detail, lng), { detail, lng })
  }

  // 邊界 1：空細節（`cbom_target("")` 可達）——不得留下未插值的佔位符
  check(`${lng} 空細節`, renderCbomFailure(t, 'cbom.err.target_not_archive', '', lng), { lng })

  // 邊界 2：detail 為 null / undefined（`reason_detail` 在序列化時可省略）
  check(`${lng} null 細節`, renderCbomFailure(t, 'cbom.err.target_not_archive', null, lng), {
    lng,
  })
  check(`${lng} undefined 細節`, renderCbomFailure(t, 'cbom.err.timeout', undefined, lng), {
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

if (problems.length > 0) {
  console.error('✗ CBOM 成因渲染有問題（報表會把這些字面印給交件對象看）：')
  for (const p of problems) console.error(`    - ${p}`)
  process.exit(1)
}

console.log(
  `✓ CBOM 成因渲染檢查通過（${CBOM_ERROR_KEYS.length} 鍵 × 2 語系 + 5 類邊界，共 ${checked} 個案例；` +
    `驗的是 src/cbom.ts 的 renderCbomFailure 本身，非副本）`,
)
