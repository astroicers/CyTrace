import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { ThemeProvider } from 'next-themes'
import i18n from '../i18n' // 共用 i18n 初始化（與報表同一組 locales）
import './console.css'
import { SessionProvider } from './state/session'
import { App } from './App'

// 語言持久化（console 特有；report 是 file:// 單檔不做持久化）。
const savedLang = localStorage.getItem('cytrace.lang')
if (savedLang) {
  void i18n.changeLanguage(savedLang)
  document.documentElement.lang = savedLang
}
i18n.on('languageChanged', (lng) => localStorage.setItem('cytrace.lang', lng))

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider attribute="class" defaultTheme="light" disableTransitionOnChange>
      <SessionProvider>
        <App />
      </SessionProvider>
    </ThemeProvider>
  </StrictMode>,
)
