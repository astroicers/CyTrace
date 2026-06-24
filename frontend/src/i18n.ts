import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
// 與 Rust CLI 共用同一組 locale（ADR-004 單一來源）。
import zhTW from '../../locales/zh-TW.json'
import enUS from '../../locales/en-US.json'

export const SUPPORTED_LANGS = [
  { code: 'zh-TW', label: '繁體中文' },
  { code: 'en-US', label: 'English' },
] as const

void i18n.use(initReactI18next).init({
  resources: {
    'zh-TW': { translation: zhTW },
    'en-US': { translation: enUS },
  },
  lng: 'zh-TW',
  fallbackLng: 'zh-TW',
  interpolation: { escapeValue: false },
})

export default i18n
