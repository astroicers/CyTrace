// console 的 job 錯誤顯示邏輯（與 render 分離，便於被檢查腳本 import）。
//
// 放在純 .ts 而非 .tsx：Node 的型別剝離（--experimental-strip-types）只剝型別，
// 不轉換 JSX，故 .tsx 無法被 frontend/scripts/cbom-message-check.mts 直接 import。
// 分離的另一個理由見下方函式註解。

import type { TFunction } from 'i18next'
import { renderCbomFailure } from '../cbom.ts'

/**
 * 決定 job 錯誤要顯示什麼文字，以及 `detail` 是否已被那段文字用掉。
 *
 * 抽成純函式有兩個理由：這頁沒有任何 render 層測試（`tsc -b` 與 `make lint` 都看不到
 * 它），而「訊息」與「detail 要不要再印」在兩處各判一次必然會不同步——第十輪複審
 * 抓到的正是這個：退回路徑讓 `<p>` 印了 detail，`<pre>` 又印一次，
 * 而同一個 commit 在 CLI 側正好斷言「細節不得重複出現」。
 */
export function describeJobError(
  error: { i18n_key: string; detail?: string | null },
  t: TFunction,
  lang: string,
): { text: string; detailConsumed: boolean } {
  const key = error.i18n_key
  if (key.startsWith('cbom.err.')) {
    // 成因已含細節（renderCbomFailure 會插值或附在括號內），不再重複印
    return { text: renderCbomFailure(t, key, error.detail, lang), detailConsumed: true }
  }
  const msg = key ? t(key) : ''
  // t() 查不到時回傳鍵本身；裸鍵與空白對操作員都等於沒有訊息
  if (!msg || msg === key) {
    if (error.detail) return { text: error.detail, detailConsumed: true }
    return { text: t('console.common.error'), detailConsumed: false }
  }
  return { text: msg, detailConsumed: false }
}

