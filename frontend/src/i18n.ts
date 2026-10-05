import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
// 與 Rust CLI 共用同一組 locale（ADR-004 單一來源）。
// `with { type: 'json' }` 與 `.ts` 副檔名：讓 node 的型別剝離能直接載入本檔，
// 檢查腳本因此驗的是 **app 自己的 i18n 實例**，不是手抄一份設定（T909 第二輪複審 lang#1）。
import zhTW from '../../locales/zh-TW.json' with { type: 'json' }
import enUS from '../../locales/en-US.json' with { type: 'json' }

import { DEFAULT_LANG, initialLang, type LangCode } from './langs.ts'

export { SUPPORTED_LANGS } from './langs.ts'

void i18n.use(initReactI18next).init({
  // 鍵必須恰為 SUPPORTED_LANGS 的語系碼：鍵若漂成 'en'，i18next 會把 en-US 解析成 'en'，
  // effectiveLang 不認而送出 zh-TW——英文介面收中文錯誤（T909 第二輪完整性批判）
  resources: {
    'zh-TW': { translation: zhTW },
    'en-US': { translation: enUS },
  } satisfies Record<LangCode, { translation: unknown }>,
  // 報表：Rust 產生時依 --lang／請求語系寫入 <html lang>，以它開啟（T918）。
  // console：console.html 固定 zh-TW，之後由 console/main.tsx 還原存過的語系。
  // node 檢查腳本沒有 document → DEFAULT_LANG。
  lng: initialLang(globalThis.document?.documentElement?.lang),
  fallbackLng: DEFAULT_LANG,
  interpolation: { escapeValue: false },
})

export default i18n
