/**
 * console 送給 server 的語系 == 畫面實際顯示的語系（T909）。
 *
 * **驗的是實際送出的東西**：載入真的 `src/console/api/client.ts`、`upload.ts` 與 app 自己的
 * i18n 實例（`src/i18n.ts`），stub 掉 `fetch` / `XMLHttpRequest`，斷言實際送出的
 * `Accept-Language` header 與導覽 URL 的 `?lang=`。
 *
 * 初版只驗 `langs.ts` 的 helper：把 client.ts 的 `uiLanguage` 改回讀 `i18n.language`、把 main.tsx
 * 的白名單拿掉、或把語系 header 整行移進註解，本檢查與 Rust 契約測試全綠——原 bug 可以在所有
 * 閘全綠下整個回來（T909 第二輪複審 lang#0 / tests#0 / claims#2，3/3 確認）。
 *
 * 帶 DOM 的檔案（main.tsx、.tsx 元件）node 載不起來，只能文字釘住；為此把可測的邏輯都抽成
 * 純函式（`restoreSavedLang`、`appendLang`），文字閘只釘「呼叫了它」與「沒有繞過它」，
 * 而且先剝註解再比對。
 *
 * 跑法：node --experimental-strip-types frontend/scripts/console-lang-check.mts
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

// ── stub：必須在載入 client.ts / upload.ts 前就緒 ──
type Call = { url: string; headers: Record<string, string> }
const fetchCalls: Call[] = []
globalThis.fetch = (async (url: string, init?: RequestInit) => {
  fetchCalls.push({ url, headers: { ...(init?.headers as Record<string, string>) } })
  return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
}) as typeof fetch

class FakeXHR {
  static sent: FakeXHR[] = []
  method = ''
  url = ''
  headers: Record<string, string> = {}
  upload: Record<string, unknown> = {}
  withCredentials = false
  status = 0
  responseText = ''
  open(method: string, url: string) {
    this.method = method
    this.url = url
  }
  setRequestHeader(k: string, v: string) {
    this.headers[k] = v
  }
  send() {
    FakeXHR.sent.push(this)
  }
  abort() {}
}
;(globalThis as unknown as { XMLHttpRequest: unknown }).XMLHttpRequest = FakeXHR

// ── 真實作 ──
const { default: i18n } = await import('../src/i18n.ts')
const { api, artifactUrl, uiLanguage } = await import('../src/console/api/client.ts')
const { uploadScan } = await import('../src/console/api/upload.ts')
const { fmtTime } = await import('../src/console/format.ts')
const L = await import('../src/langs.ts')

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const CODES: readonly string[] = L.SUPPORTED_LANGS.map((l) => l.code)
const failures: string[] = []
const fail = (m: string) => failures.push(m)

// 判斷「畫面是哪一語」的探針鍵：各語系譯文必須互不相同，否則比對不含資訊
const PROBE = 'server.err.bad_request'
const probeOf = (lng: string) => i18n.getResource(lng, 'translation', PROBE) as string | undefined
if (new Set(CODES.map(probeOf)).size !== CODES.length || CODES.some((c) => !probeOf(c))) {
  fail(`探針鍵 ${PROBE} 在各語系須存在且互不相同`)
}

// ── 1. 端到端：任何進入 i18n 的值，實際送出的語系都必須是畫面語系 ──
// 刻意繞過 main.tsx 的白名單直接 changeLanguage：白名單是第一道，本段驗第二道單獨也守得住。
// 涵蓋：精確值、只差地區或大小寫、只有語言碼、不支援語系、非 Latin-1、
// i18next 的保留值（dev / cimode：resolvedLanguage 為 undefined → 走 fallback 分支）、三段式碼。
const RAW = [
  'zh-TW', 'en-US', 'en', 'en-GB', 'EN-us', 'zh', 'zh-CN', 'fr', '中文',
  'dev', 'cimode', 'en-US-POSIX', 'zh-Hant-TW',
]
const ISO = '2026-03-04T05:06:07Z'
let diverged = 0
let fallbackHit = 0
for (const raw of RAW) {
  await i18n.changeLanguage(raw)
  const tag = `raw=${JSON.stringify(raw)}`
  const sent = uiLanguage()
  if (typeof sent !== 'string' || !CODES.includes(sent)) {
    fail(`${tag}：uiLanguage() 送出不支援的值 ${JSON.stringify(sent)}`)
    continue
  }
  if (i18n.language !== sent) diverged++
  if (i18n.resolvedLanguage === undefined) fallbackHit++
  // 畫面一致（cimode 畫面顯示鍵名，無從比對；dev 仍顯示 fallback 語系，照比）
  if (raw !== 'cimode' && i18n.t(PROBE) !== probeOf(sent)) {
    fail(`${tag}：畫面顯示「${i18n.t(PROBE)}」，uiLanguage() 卻是 ${sent}`)
  }
  // fetch 路徑：實際送出的 header
  fetchCalls.length = 0
  await api.version()
  const h = fetchCalls.at(-1)?.headers['Accept-Language']
  if (h !== sent) fail(`${tag}：fetch 實際送出 Accept-Language=${JSON.stringify(h)}，應為 ${sent}`)
  // 上傳 XHR 路徑（Promise executor 同步執行，open / setRequestHeader 已發生）
  FakeXHR.sent.length = 0
  void uploadScan(new File(['x'], 'a.tar'), undefined, () => {}).promise.catch(() => {})
  const x = FakeXHR.sent.at(-1)
  if (x?.url !== '/api/v1/jobs/upload' || x.headers['Accept-Language'] !== sent) {
    fail(`${tag}：上傳 XHR 實際送出 ${JSON.stringify(x?.headers)}（${x?.url}），應帶 ${sent}`)
  }
  // 導覽路徑：`<a href>` 設不了 header，只能靠 ?lang=
  for (const [label, u, download] of [
    ['report', artifactUrl.report('j1'), null],
    ['report+download', artifactUrl.report('j1', true), '1'],
    ['result', artifactUrl.result('j1'), null],
  ] as const) {
    const q = new URL(u, 'http://h').searchParams
    if (q.getAll('lang').length !== 1 || q.get('lang') !== sent || q.get('download') !== download) {
      fail(`${tag}：${label} 導覽 URL ${u} 應恰帶 lang=${sent}${download ? `、download=${download}` : ''}`)
    }
  }
  // 時間格式跟 UI 語系，不跟 runtime 預設
  const want = new Date(ISO).toLocaleString(sent)
  if (fmtTime(ISO) !== want) fail(`${tag}：fmtTime 得「${fmtTime(ISO)}」，應為 ${sent} 格式「${want}」`)
}
// 反空轉：案例必須真的走到「要求≠送出」與 fallback 分支，時間格式必須因語系而異
if (diverged < 6) fail(`只有 ${diverged} 個案例的 i18n.language 與送出值不同——案例失去鑑別力`)
if (fallbackHit < 2) fail(`只有 ${fallbackHit} 個案例走到 effectiveLang 的 fallback 分支（dev / cimode）`)
if (new Set(CODES.map((c) => new Date(ISO).toLocaleString(c))).size !== CODES.length) {
  fail('各語系的時間格式相同——fmtTime 的檢查不含資訊（runtime 缺 ICU？）')
}

// ── 2. 純函式 ──
if (L.effectiveLang({}) !== L.DEFAULT_LANG) fail('effectiveLang({}) 應回預設語系')
if (L.effectiveLang({ resolvedLanguage: 'en' }) !== L.DEFAULT_LANG) fail('effectiveLang(en) 應回預設語系')
if (L.effectiveLang({ resolvedLanguage: 'en-US' }) !== 'en-US') fail('effectiveLang(en-US) 應回 en-US')
for (const v of ['en', '中文', 'EN-us', null, '', 'cimode', 'en-US', 'zh-TW']) {
  const keys: string[] = []
  const got = L.restoreSavedLang({ getItem: (k: string) => (keys.push(k), v) })
  const want = v !== null && CODES.includes(v) ? v : null
  if (got !== want) fail(`restoreSavedLang(存值 ${JSON.stringify(v)}) 得 ${JSON.stringify(got)}，應為 ${JSON.stringify(want)}`)
  if (keys.join() !== L.LANG_STORAGE_KEY) fail(`restoreSavedLang 讀了 ${JSON.stringify(keys)}，應只讀 ${L.LANG_STORAGE_KEY}`)
}
for (const [url, lang, wantPath, wantQs] of [
  ['/x', 'zh-TW', '/x', { lang: 'zh-TW' }],
  ['/x?download=1', 'en-US', '/x', { download: '1', lang: 'en-US' }],
  ['/x', 'a b&c=d', '/x', { lang: 'a b&c=d' }],
] as const) {
  const u = new URL(L.appendLang(url, lang), 'http://h')
  const qs = Object.fromEntries(u.searchParams)
  if (u.pathname !== wantPath || JSON.stringify(qs) !== JSON.stringify(wantQs)) {
    fail(`appendLang(${url}, ${lang}) 得 ${u.pathname}?${u.searchParams}，應為 ${JSON.stringify(wantQs)}`)
  }
}

// ── 3. 文字閘：node 載不起來的檔案（.tsx、main.tsx）只能釘接線，且先剝註解 ──
/** 剝掉 // 與 /* *\/ 註解（保留字串字面值內的內容與行結構）。 */
export function stripComments(src: string): string {
  let out = ''
  let i = 0
  let q: string | null = null
  while (i < src.length) {
    const c = src[i]
    const n = src[i + 1]
    if (q) {
      out += c
      if (c === '\\') {
        out += n ?? ''
        i += 2
        continue
      }
      if (c === q) q = null
      i++
    } else if (c === '/' && n === '/') {
      while (i < src.length && src[i] !== '\n') i++
    } else if (c === '/' && n === '*') {
      i += 2
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') out += '\n'
        i++
      }
      i += 2
    } else {
      if (c === "'" || c === '"' || c === '`') q = c
      out += c
      i++
    }
  }
  return out
}
// 禁止繞過 effectiveLang 讀語系：原 bug 與複審找到的 LangSwitch / JobDetailPage / fmtTime 都是這一型
const BANNED: Array<[RegExp, string]> = [
  [/\bi18n\.languages?\b/, '讀 i18n.language(s)——改用 effectiveLang(i18n)'],
  [/\bnavigator\.languages?\b/, '讀瀏覽器語系——UI 語系才是事實源'],
  [/\.toLocale\w*String\(\s*\)/, '不帶 locale 的 toLocale*String()——會用 runtime 預設語系'],
]
// 比對器的正負對照：壞樣本必中、只在註解或字串裡出現必不中
const SELF = [
  ['x = i18n.language', 1],
  ['d.toLocaleString()', 1],
  ['// i18n.language 在註解裡', 0],
  ["s = 'http://x' // i18n.language", 0],
  ['/* navigator.language */ y', 0],
] as const
for (const [src, want] of SELF) {
  const got = BANNED.filter(([re]) => re.test(stripComments(src))).length
  if (got !== want) fail(`比對器自檢：${JSON.stringify(src)} 命中 ${got} 次，應為 ${want}`)
}
function walk(dir: string, out: string[] = []): string[] {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) walk(p, out)
    else if (/\.(ts|tsx)$/.test(e.name)) out.push(p)
  }
  return out
}
const files = walk(path.join(ROOT, 'frontend/src'))
if (files.length < 25) fail(`只掃到 ${files.length} 個前端檔——掃描可能失效`)
for (const f of files) {
  const rel = path.relative(ROOT, f)
  stripComments(fs.readFileSync(f, 'utf8'))
    .split('\n')
    .forEach((line, n) => {
      for (const [re, why] of BANNED) if (re.test(line)) fail(`${rel}:${n + 1}：${why}`)
    })
}
const main = stripComments(fs.readFileSync(path.join(ROOT, 'frontend/src/console/main.tsx'), 'utf8'))
if (!main.includes('restoreSavedLang(localStorage)')) fail('main.tsx 未經 restoreSavedLang 讀回存的語系')
if (/localStorage\.getItem\(/.test(main)) fail('main.tsx 直接讀 localStorage——白名單被繞過')

if (failures.length) {
  console.error(`✗ console 語系檢查失敗（${failures.length}）：\n  ${failures.join('\n  ')}`)
  process.exit(1)
}
console.log(
  `✓ console 語系檢查通過（${RAW.length} 種輸入 × fetch / XHR / 導覽 URL / 時間格式，實際送出值皆為畫面語系；` +
    `${diverged} 種要求≠送出、${fallbackHit} 種走 fallback；${files.length} 檔無繞過 effectiveLang 的讀法）`,
)
