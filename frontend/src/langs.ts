/**
 * 支援語系的單一事實源（與 Rust `cytrace_i18n::Lang` 對應）。
 *
 * 刻意**不** import locale JSON：node 的型別剝離檢查腳本要能直接載入本檔驗真實作
 * （`i18n.ts` 的 JSON import 在 node 下需 import attribute，載不起來）。
 */
export const SUPPORTED_LANGS = [
  { code: 'zh-TW', label: '繁體中文' },
  { code: 'en-US', label: 'English' },
] as const

export type LangCode = (typeof SUPPORTED_LANGS)[number]['code']

export const DEFAULT_LANG: LangCode = 'zh-TW'

/** 只接受有資源的語系碼；`en`、`en-GB`、`cimode`、localStorage 裡的任意值一律 null。 */
export function supportedLang(code: string | null | undefined): LangCode | null {
  return SUPPORTED_LANGS.find((l) => l.code === code)?.code ?? null
}

/**
 * 畫面**實際**使用的語系——送給 server 的必須是它。
 *
 * 不能用 `i18n.language`：它是「被要求的」語系，不是「被解析出的」。localStorage 存了
 * `en` 時 `language === 'en'`、畫面卻 fallback 成中文，server 收 `Accept-Language: en`
 * 協商成 en-US，於是中文介面裡跳英文錯誤；存了非 Latin-1 的值時瀏覽器建 header 直接
 * 丟 TypeError，被 client 包成 network 錯誤，每次登入都失敗。
 *
 * （T909 對抗式複審 v19：反證票 0/3——三票都判「app 自己寫不出這類值」而不可達。
 * 仍修為防禦：localStorage 可被手改、舊版或別的工具寫入，而代價只是一個純函式。）
 *
 * 讀語系的地方**一律**經本函式（送出、顯示、格式化），`i18n.language` 在 `src/` 內禁用——
 * `frontend/scripts/console-lang-check.mts` 機械把關。
 */
export function effectiveLang(i18n: { resolvedLanguage?: string }): LangCode {
  return supportedLang(i18n.resolvedLanguage) ?? DEFAULT_LANG
}

/** console 持久化 UI 語系的 localStorage 鍵。 */
export const LANG_STORAGE_KEY = 'cytrace.lang'

/**
 * 讀回存過的 UI 語系；存值不可信（手改、舊版、別的工具寫入），只接受有資源的語系。
 *
 * 抽成純函式（storage 由呼叫端注入）是為了讓檢查腳本能驗**真實作**——main.tsx 帶 DOM，
 * node 載不起來；白名單寫在那裡時，拿掉它沒有任何檢查會紅（T909 第二輪複審 lang#0）。
 */
export function restoreSavedLang(storage: Pick<Storage, 'getItem'>): LangCode | null {
  return supportedLang(storage.getItem(LANG_STORAGE_KEY))
}

/**
 * 在 URL 附上 `lang=` 查詢參數：已有查詢字串時以 `&` 接，否則以 `?` 起頭。
 *
 * 純函式以便行為檢查：分隔符寫錯時 `/report?download=1?lang=…` 會讓 server 把
 * `download` 解成 `1?lang=zh-TW` 而回 400——下載鈕整個壞掉、語系也沒送到
 * （T909 第二輪複審 tests#1：原本只有字串比對，改壞了所有閘仍綠）。
 */
export function appendLang(url: string, lang: string): string {
  const sep = url.includes('?') ? '&' : '?'
  return `${url}${sep}lang=${encodeURIComponent(lang)}`
}
