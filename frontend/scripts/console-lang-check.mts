/**
 * console 送給 server 的語系 == 畫面實際顯示的語系（T909）。
 *
 * **驗的是實際送出的東西**：載入真的 `src/console/api/client.ts`、`upload.ts` 與 app 自己的
 * i18n 實例（`src/i18n.ts`），stub 掉 `fetch` / `XMLHttpRequest`，攔下實際送出的
 * `Accept-Language` header 與導覽 URL 的 `?lang=`。
 *
 * 歷程（每一版都被複審找到「改壞了仍綠」的寫法）：
 * - 初版只驗 `langs.ts` 的 helper——client.ts 改回讀 `i18n.language` 仍綠（第二輪 lang#0）。
 * - 第二版只呼叫 `api.version()`（GET、無 body）——request() 的變更型分支丟掉 header 仍綠；
 *   導覽 URL 只列舉 report / result，新增的 artifactUrl 成員看不到（第三輪 lang#0、完整性批判）。
 *   本版**自動枚舉** `api` 與 `artifactUrl` 的每一個成員，新增的方法自動納入。
 * - FakeXHR 原本不管狀態一律收 header，且在 send 之後才讀——瀏覽器會丟例外、或根本沒送出的
 *   header 照算「已送出」（第三輪 lang#1）。本版依 WHATWG XHR 狀態機、send 時存快照。
 * - 禁讀規則原本是剝註解後的 regex，`i18n: { language }` 解構、`toLocaleString(undefined, …)`、
 *   `Intl.DateTimeFormat()`、含 `\//` 的 regex 字面值都繞得過（第三輪 lang#2）。本版用 TypeScript AST。
 *
 * 跑法：node --experimental-strip-types frontend/scripts/console-lang-check.mts
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

// ── stub：必須在載入 client.ts / upload.ts 前就緒 ──
type Call = { url: string; method: string; headers: Record<string, string>; hasBody: boolean }
const fetchCalls: Call[] = []
globalThis.fetch = (async (url: string, init?: RequestInit) => {
  fetchCalls.push({
    url,
    method: init?.method ?? 'GET',
    headers: { ...(init?.headers as Record<string, string>) },
    hasBody: init?.body != null,
  })
  return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
}) as typeof fetch

/** 依 WHATWG XHR 的狀態機：OPENED 之外呼叫 setRequestHeader / send 一律丟 InvalidStateError。 */
class FakeXHR {
  static sent: Array<{ url: string; method: string; headers: Record<string, string> }> = []
  state: 'unsent' | 'opened' | 'sent' = 'unsent'
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
    this.headers = {}
    this.state = 'opened'
  }
  setRequestHeader(k: string, v: string) {
    if (this.state !== 'opened') {
      throw new DOMException(`setRequestHeader() 只能在 OPENED 狀態、send() 之前呼叫（目前 ${this.state}）`, 'InvalidStateError')
    }
    this.headers[k] = k in this.headers ? `${this.headers[k]}, ${v}` : v
  }
  send() {
    if (this.state !== 'opened') throw new DOMException('send() 只能在 OPENED 狀態呼叫', 'InvalidStateError')
    this.state = 'sent'
    // 快照：送出那一刻的 header；之後再改不算送出
    FakeXHR.sent.push({ url: this.url, method: this.method, headers: { ...this.headers } })
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

// 自動枚舉：新增的 api 方法／導覽 URL 成員不必改本檔就會被驗（參數一律用假值）
type AnyFn = (...a: unknown[]) => unknown
const API = Object.entries(api) as Array<[string, AnyFn]>
const NAV = Object.entries(artifactUrl) as Array<[string, AnyFn]>
const fakeArgs = (fn: AnyFn) => Array.from({ length: fn.length }, () => 'x')

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
const seenMethods = new Set<string>()
let seenBody = false
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
  // fetch 路徑：**每一個** api 方法實際送出的 header（含變更型與帶 body 的分支）
  fetchCalls.length = 0
  for (const [name, fn] of API) {
    try {
      await fn(...fakeArgs(fn))
    } catch (e) {
      fail(`${tag}：api.${name}() 丟出例外：${e}`)
    }
  }
  if (fetchCalls.length !== API.length) {
    fail(`${tag}：呼叫 ${API.length} 個 api 方法只攔到 ${fetchCalls.length} 次 fetch`)
  }
  for (const c of fetchCalls) {
    seenMethods.add(c.method)
    seenBody ||= c.hasBody
    if (c.headers['Accept-Language'] !== sent) {
      fail(`${tag}：${c.method} ${c.url} 實際送出 Accept-Language=${JSON.stringify(c.headers['Accept-Language'])}，應為 ${sent}`)
    }
  }
  // 上傳 XHR 路徑
  FakeXHR.sent.length = 0
  let uploadErr: unknown = null
  try {
    void uploadScan(new File(['x'], 'a.tar'), undefined, () => {}).promise.catch(() => {})
  } catch (e) {
    uploadErr = e
  }
  const x = FakeXHR.sent.at(-1)
  if (x?.url !== '/api/v1/jobs/upload' || x.headers['Accept-Language'] !== sent) {
    fail(`${tag}：上傳 XHR 送出 ${JSON.stringify(x)}${uploadErr ? `（例外：${uploadErr}）` : ''}，應帶 ${sent}`)
  }
  // 導覽路徑：`<a href>` 設不了 header，只能靠 ?lang=；每個成員各以有／無第二參數呼叫
  for (const [name, fn] of NAV) {
    for (const args of [['j1'], ['j1', true]]) {
      const u = String(fn(...args))
      const q = new URL(u, 'http://h').searchParams
      if (q.getAll('lang').length !== 1 || q.get('lang') !== sent) {
        fail(`${tag}：artifactUrl.${name}(${args.join(', ')}) = ${u}，應恰帶一個 lang=${sent}`)
      }
    }
  }
  const dl = new URL(artifactUrl.report('j1', true), 'http://h').searchParams
  if (dl.get('download') !== '1') fail(`${tag}：下載 URL 的 download 參數被破壞：${artifactUrl.report('j1', true)}`)
  // 時間格式跟 UI 語系，不跟 runtime 預設
  const want = new Date(ISO).toLocaleString(sent)
  if (fmtTime(ISO) !== want) fail(`${tag}：fmtTime 得「${fmtTime(ISO)}」，應為 ${sent} 格式「${want}」`)
}
// 反空轉：案例必須真的走到「要求≠送出」、fallback 分支、變更型與帶 body 的請求
if (diverged < 6) fail(`只有 ${diverged} 個案例的 i18n.language 與送出值不同——案例失去鑑別力`)
if (fallbackHit < 2) fail(`只有 ${fallbackHit} 個案例走到 effectiveLang 的 fallback 分支（dev / cimode）`)
if (API.length < 8 || NAV.length < 2) fail(`只枚舉到 ${API.length} 個 api 方法、${NAV.length} 個導覽成員——枚舉可能失效`)
if (![...seenMethods].some((m) => m !== 'GET')) fail('沒有任何變更型請求被驗到（只有 GET）')
if (!seenBody) fail('沒有任何帶 body 的請求被驗到')
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

// ── 3. AST 閘：node 載不起來的檔案（.tsx、main.tsx）只能靜態釘住 ──
// 讀語系一律經 effectiveLang；日期／數字格式化只准在 console/format.ts（它有上面的行為檢查）。
const LANG_PROPS = new Set(['language', 'languages'])
const FORMAT_HOME = 'frontend/src/console/format.ts'
function bannedUses(file: string, src: string): string[] {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true,
    file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
  const out: string[] = []
  const at = (n: ts.Node, why: string) =>
    out.push(`${file}:${sf.getLineAndCharacterOfPosition(n.getStart()).line + 1}：${why}`)
  const visit = (n: ts.Node) => {
    if (ts.isPropertyAccessExpression(n) && LANG_PROPS.has(n.name.text)) {
      at(n, `讀 .${n.name.text}——改用 effectiveLang(i18n)`)
    }
    if (ts.isElementAccessExpression(n) && ts.isStringLiteralLike(n.argumentExpression)
      && LANG_PROPS.has(n.argumentExpression.text)) {
      at(n, `讀 ["${n.argumentExpression.text}"]——改用 effectiveLang(i18n)`)
    }
    if (ts.isBindingElement(n)) {
      const key = n.propertyName ?? n.name
      if ((ts.isIdentifier(key) || ts.isStringLiteral(key)) && LANG_PROPS.has(key.text)) {
        at(n, `解構取出 ${key.text}——改用 effectiveLang(i18n)`)
      }
    }
    if (file !== FORMAT_HOME) {
      if (ts.isPropertyAccessExpression(n) && /^toLocale\w*String$/.test(n.name.text)) {
        at(n, `${n.name.text} 只准在 ${FORMAT_HOME}（依 UI 語系格式化）`)
      }
      if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'Intl') {
        at(n, `Intl.${n.name.text} 只准在 ${FORMAT_HOME}`)
      }
    }
    ts.forEachChild(n, visit)
  }
  visit(sf)
  return out
}
// 比對器的正負對照：壞樣本必中、只在註解／字串／regex 裡出現必不中
const SELF: Array<[string, number]> = [
  ['x = i18n.language', 1],
  ['x = i18n["languages"]', 1],
  ['const { t, i18n: { language } } = useTranslation()', 1],
  ["const { 'language': l } = i18n", 1],
  ['d.toLocaleString()', 1],
  ["d.toLocaleString(undefined, { dateStyle: 'medium' })", 1],
  ['new Intl.DateTimeFormat().format(d)', 1],
  ['const abs = /^https?:\\/\\//.test(u) ? u : i18n.language', 1],
  ["s.replace(/'/g, '’'); const h = 'file://' + navigator.language", 1],
  ['// i18n.language 在註解裡', 0],
  ["const s = 'i18n.language 在字串裡'", 0],
  ['const r = /i18n\\.language/', 0],
  ['x = i18n.resolvedLanguage; document.documentElement.lang = x', 0],
]
for (const [src, want] of SELF) {
  const got = bannedUses('frontend/src/Sample.tsx', src).length
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
  for (const hit of bannedUses(path.relative(ROOT, f).replace(/\\/g, '/'), fs.readFileSync(f, 'utf8'))) fail(hit)
}
// main.tsx（帶 DOM，載不起來）：白名單接線
const mainFile = path.join(ROOT, 'frontend/src/console/main.tsx')
const mainSf = ts.createSourceFile(mainFile, fs.readFileSync(mainFile, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
let restores = 0
let rawReads = 0
const scanMain = (n: ts.Node) => {
  if (ts.isCallExpression(n)) {
    const callee = n.expression.getText(mainSf)
    if (callee === 'restoreSavedLang' && n.arguments[0]?.getText(mainSf) === 'localStorage') restores++
    if (/(^|\.)localStorage\.getItem$/.test(callee)) rawReads++
  }
  ts.forEachChild(n, scanMain)
}
scanMain(mainSf)
if (restores !== 1) fail(`main.tsx 應恰呼叫一次 restoreSavedLang(localStorage)，實際 ${restores} 次`)
if (rawReads) fail('main.tsx 直接讀 localStorage——白名單被繞過')

if (failures.length) {
  console.error(`✗ console 語系檢查失敗（${failures.length}）：\n  ${failures.join('\n  ')}`)
  process.exit(1)
}
console.log(
  `✓ console 語系檢查通過（${RAW.length} 種輸入 × ${API.length} 個 api 方法 / 上傳 XHR / ${NAV.length} 個導覽成員 / 時間格式，` +
    `實際送出值皆為畫面語系；${diverged} 種要求≠送出、${fallbackHit} 種走 fallback；${files.length} 檔 AST 無繞過 effectiveLang 的讀法）`,
)
