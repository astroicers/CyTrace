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
 * 丟 TypeError，被 client 包成 network 錯誤，每次登入都失敗（T909 對抗式複審，2/3 確認）。
 */
export function effectiveLang(i18n: { resolvedLanguage?: string }): LangCode {
  return supportedLang(i18n.resolvedLanguage) ?? DEFAULT_LANG
}
