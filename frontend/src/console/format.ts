// 共用格式化（ISO → 當地顯示）。避免各頁重複。
import i18n from '../i18n.ts'
import { effectiveLang } from '../langs.ts'

/**
 * 時間依 **UI 語系**格式化，不是瀏覽器語系。
 *
 * 原本 `toLocaleString()` 不帶 locale——用的是 JS runtime 預設（瀏覽器語系），與 i18n 無關：
 * 瀏覽器 en-US 的使用者一進 console 就是「中文介面配英文時間」，切成 en-US 後反過來
 * （T806 起既有；T909 第二輪複審 lang#2）。呼叫端皆在 useTranslation 的元件內，切語系即重繪。
 */
export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(effectiveLang(i18n))
}
