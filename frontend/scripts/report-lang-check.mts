/**
 * 報表開啟語言 == `<html lang>`（Rust 產生時依 `--lang`／請求語系寫入；T918）。
 *
 * **驗的是 app 自己的 i18n 實例**：每個案例開一個子程序，先放好假的 `document`，
 * 再載入真的 `src/i18n.ts`，讀它初始化後的 `resolvedLanguage`。i18next 的預設實例是
 * 全域單例，同一個程序裡重新 init 會留著上一個案例的狀態，所以一案一程序。
 *
 * `i18n.ts` 改回寫死 `lng: DEFAULT_LANG`，或 `initialLang` 不再讀參數，en-US 案例就會紅。
 * Rust 端「產生時確實寫入」由 cytrace-report 與 CLI／server 的測試涵蓋。
 *
 * 跑法：node --experimental-strip-types frontend/scripts/report-lang-check.mts
 */
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const self = fileURLToPath(import.meta.url)
const NO_DOCUMENT = '<no-document>'

// ── 子程序：設好 document 後載入真的 i18n.ts，印出解析後的語系 ──
if (process.argv[2] === '--child') {
  const htmlLang = process.argv[3]
  if (htmlLang !== NO_DOCUMENT) {
    ;(globalThis as { document?: unknown }).document = { documentElement: { lang: htmlLang } }
  }
  const { default: i18n } = await import('../src/i18n.ts')
  process.stdout.write(String(i18n.resolvedLanguage))
  process.exit(0)
}

// ── 主程序 ──
const CASES: [string, string][] = [
  ['en-US', 'en-US'],
  ['zh-TW', 'zh-TW'],
  // 只接受有資源的語系碼；其餘一律 zh-TW（不猜、不做前綴比對——Rust 寫入的一定是正規碼）
  ['en', 'zh-TW'],
  ['en-GB', 'zh-TW'],
  // 以下兩案分得出「有沒有白名單」：沒有 initialLang 過濾時，i18next 會把 en-us 正規化成 en-US、
  // cimode 會讓 resolvedLanguage 變成 undefined（T918 複審 L1）
  ['en-us', 'zh-TW'],
  ['cimode', 'zh-TW'],
  ['fr-FR', 'zh-TW'],
  ['', 'zh-TW'],
  [NO_DOCUMENT, 'zh-TW'],
]

const errors: string[] = []
for (const [htmlLang, want] of CASES) {
  const got = execFileSync(
    process.execPath,
    ['--experimental-strip-types', '--no-warnings', self, '--child', htmlLang],
    { encoding: 'utf8' },
  ).trim()
  if (got !== want) errors.push(`<html lang="${htmlLang}"> → 開啟語言 ${got}，應為 ${want}`)
}

if (errors.length) {
  console.error('✗ 報表開啟語言檢查失敗：')
  for (const e of errors) console.error('  ' + e)
  process.exit(1)
}
console.log(`✓ 報表開啟語言檢查通過（${CASES.length} 種 <html lang>，載入真的 src/i18n.ts）`)
