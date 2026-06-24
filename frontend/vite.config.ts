import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'

// 單檔內聯 build（ADR-005）：所有 JS/CSS 內聯進一個 index.html，零外部請求。
// cytrace-report 會把 <!--CYTRACE_DATA--> 換成注入的 ScanResult（ADR-009）。
export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  build: {
    target: 'es2022',
    cssCodeSplit: false,
    assetsInlineLimit: 100_000_000,
    chunkSizeWarningLimit: 100_000_000,
    reportCompressedSize: false,
  },
})
