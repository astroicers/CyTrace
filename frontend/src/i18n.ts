import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
// 與 Rust CLI 共用同一組 locale（ADR-004 單一來源）。
import zhTW from '../../locales/zh-TW.json'
import enUS from '../../locales/en-US.json'

import { DEFAULT_LANG } from './langs'

export { SUPPORTED_LANGS } from './langs'

void i18n.use(initReactI18next).init({
  resources: {
    'zh-TW': { translation: zhTW },
    'en-US': { translation: enUS },
  },
  lng: DEFAULT_LANG,
  fallbackLng: DEFAULT_LANG,
  interpolation: { escapeValue: false },
})

export default i18n
