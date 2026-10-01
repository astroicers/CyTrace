/**
 * console 送給 server 的語系 == 畫面實際顯示的語系（T909 對抗式複審 v1，2/3 確認）。
 *
 * **import 真實作 `effectiveLang`**，搭配一個與 app 同設定的真 i18next 實例——語系清單與
 * fallback 由 `src/langs.ts` 推導，不在本檔手抄（`src/i18n.ts` 也從同一處取）。
 *
 * 不變式對**任何**進入 i18n 的值都要成立，所以刻意繞過 main.tsx 的白名單直接
 * `changeLanguage(raw)`：白名單是第一道，`effectiveLang` 是第二道，本檔驗第二道單獨也守得住。
 *
 * 跑法：node --experimental-strip-types frontend/scripts/console-lang-check.mts
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import i18n from 'i18next'
// ← 真實作。改壞它，本檔必須轉紅。
import { DEFAULT_LANG, SUPPORTED_LANGS, effectiveLang, supportedLang } from '../src/langs.ts'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const resources = Object.fromEntries(
  SUPPORTED_LANGS.map((l) => [
    l.code,
    { translation: JSON.parse(fs.readFileSync(path.join(ROOT, `locales/${l.code}.json`), 'utf8')) },
  ]),
)
await i18n.init({
  resources,
  lng: DEFAULT_LANG,
  fallbackLng: DEFAULT_LANG,
  interpolation: { escapeValue: false },
})

// 用來判斷「畫面是哪一語」的探針鍵：各語系譯文必須互不相同，否則比對不含資訊
const PROBE = 'server.err.bad_request'
const probeOf = (lng: string) => i18n.getResource(lng, 'translation', PROBE) as string | undefined
const failures: string[] = []
const texts = SUPPORTED_LANGS.map((l) => probeOf(l.code))
if (texts.some((x) => !x) || new Set(texts).size !== texts.length) {
  failures.push(`探針鍵 ${PROBE} 在各語系須存在且互不相同：${JSON.stringify(texts)}`)
}

// 涵蓋：精確支援值、只差地區/大小寫、只有語言碼、不支援語系、非 Latin-1、空字串、測試模式
const RAW = ['zh-TW', 'en-US', 'en', 'en-GB', 'EN-us', 'zh', 'zh-CN', 'fr', '中文', '', 'cimode']
let diverged = 0
for (const raw of RAW) {
  await i18n.changeLanguage(raw)
  const sent = effectiveLang(i18n)
  if (supportedLang(sent) !== sent) {
    failures.push(`raw=${JSON.stringify(raw)}：送出不支援的語系 ${JSON.stringify(sent)}`)
    continue
  }
  // fetch 的 Headers 只收 ByteString；非 Latin-1 會丟 TypeError、被包成 network 錯誤
  if (!/^[\x20-\x7e]+$/.test(sent)) failures.push(`raw=${JSON.stringify(raw)}：送出值不能放進 header`)
  if (i18n.language !== sent) diverged++
  if (raw === 'cimode') continue // 測試模式畫面顯示鍵名，不比畫面
  const shown = i18n.t(PROBE)
  if (shown !== probeOf(sent)) {
    failures.push(`raw=${JSON.stringify(raw)}：畫面顯示「${shown}」，卻送出 ${sent}`)
  }
}
// 反空轉：至少要有案例讓「要求的語系」與「送出的語系」分岔，否則等於沒測到 v1 的情境
if (diverged < 3) failures.push(`只有 ${diverged} 個案例的 i18n.language 與送出值不同——案例失去鑑別力`)

// supportedLang 只認精確值
for (const raw of [...RAW, null, undefined]) {
  const want = SUPPORTED_LANGS.some((l) => l.code === raw) ? raw : null
  if (supportedLang(raw) !== want) failures.push(`supportedLang(${JSON.stringify(raw)}) 應為 ${JSON.stringify(want)}`)
}

if (failures.length) {
  console.error(`✗ console 語系檢查失敗（${failures.length}）：\n  ${failures.join('\n  ')}`)
  process.exit(1)
}
console.log(`✓ console 語系檢查通過（${RAW.length} 種輸入，${diverged} 種要求≠送出；送出值皆為有資源且與畫面一致的語系）`)
