import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Console SPA build（ADR-011；與報表 vite.config.ts 完全分離）。
// 刻意不含 vite-plugin-singlefile：console 是多 asset，由 Rust rust-embed 服務。
// 產物 → dist-console/，Makefile 複製到 crates/cytrace-server/assets/console/。
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: '/',
  build: {
    target: 'es2022',
    outDir: 'dist-console',
    emptyOutDir: true,
    rollupOptions: {
      // 相對於專案根（避免 node:path / __dirname，無 @types/node 依賴）
      input: { console: 'console.html' },
    },
  },
  server: {
    // 開發時打真後端（serve 預設 8443）。
    proxy: {
      '/api': 'http://127.0.0.1:8443',
    },
  },
})
