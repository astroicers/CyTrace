import type { ScanResult } from './types'
import sample from './sample.json'

// 讀取由 cytrace-report 注入的資料（ADR-009：<script id="cytrace-data" type="application/json">）。
// 開發/預覽時無注入 → 回退到 sample。
export function loadScanResult(): ScanResult {
  const el = document.getElementById('cytrace-data')
  if (el?.textContent) {
    try {
      return JSON.parse(el.textContent) as ScanResult
    } catch {
      /* 注入資料毀損 → 退回 sample */
    }
  }
  return sample as unknown as ScanResult
}
