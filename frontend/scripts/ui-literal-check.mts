/**
 * 前端畫面不得硬編碼使用者可見字串（CLAUDE.md「i18n 雙語強制」；T917）。
 *
 * v0.4.0 的報表裡留著 `Generated`、`Name`／`Version`、`· N components · M findings` 等英文
 * 字面值，中文報表照樣印英文；`scripts/i18n-check.py` 只驗「被引用的鍵存在」，
 * 對「根本沒走 t() 的字串」看不見。本檢查以 TypeScript AST 掃 `frontend/src/**\/*.tsx`：
 *
 * - **jsx-text**：JSX 文字節點含任何字母。
 * - **jsx-expr**：JSX 子節點運算式（含條件／`??`／`||`／`+` 分支與模板字串）裡的字串字面值含字母。
 * - **visible-attr**：`aria-label`、`title`、`placeholder`、`alt` 等會被念出或顯示的屬性值含字母。
 * - **prose**：其他位置的字面值「像文字」——含中日韓字元、大寫開頭的單字、兩個以上的純字母單字；
 *   模板字串的固定片段只要有一個獨立的純字母單字就算（`${a} components · ${b} findings`）。
 *   抓的是先放進變數、陣列或元件 prop（`<Row value="Not configured" />`），之後才渲染的字串。
 *   比較運算元、`case`、型別字面值、import、`new Error()`、以及**白名單內**的非可見屬性
 *   （className、id、type、role…；含其內層運算式）不算。
 * - **bad-key**：`t()` 的第一個參數若是字面值，必須是帶命名空間的鍵。i18next 找不到鍵時原樣回傳，
 *   `t('No data')` 會在兩種語言都顯示英文，而 i18n-check 只認得帶命名空間的鍵，兩道閘都看不見。
 * - **emoji**：任何 Extended_Pictographic 字元。交付場域多為無彩色 emoji 字型的離線機器，
 *   ⚠️／🌐／🌙 會變成豆腐字。
 *
 * 專有名詞與單位（產品名、引擎名、`MB`）列在 [`EXEMPT_TOKENS`]，**逐項寫理由**；
 * 從字串移除這些詞之後若仍有字母，照樣判違規。
 *
 * **已知不涵蓋**：`.ts` 檔（目前只有語言自稱名與協定字串；顯示文字一律在 .tsx 經 t() 輸出）、
 * 單一個全小寫單字的一般字串（與識別字、列舉值無法區分，如 `'light'`、`'page'`）、標點（全形／半形）。
 *
 * 反空轉：每條規則、每條分支路徑各有必紅樣本，外加一份必綠樣本；另有掃描檔數與 `t()` 呼叫數的
 * 下限，以及必須被掃到的檔案清單——glob 或剖析一旦失效，「零違規」不含資訊。
 *
 * 跑法：node --experimental-strip-types frontend/scripts/ui-literal-check.mts [另一份 src 目錄]
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

// 參數可指定另一份 src（供對舊版程式碼實測本檢查會紅）；預設為本 repo 的 frontend/src
const SRC = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src')

/** 不翻譯的專有名詞與單位。新增前先想：它真的在兩種語言裡寫法相同嗎？ */
const EXEMPT_TOKENS: Record<string, string> = {
  CyTrace: '產品名',
  Syft: '引擎名（第三方工具）',
  Grype: '引擎名（第三方工具）',
  'CBOMkit-theia': '引擎名（第三方工具）',
  MB: '容量單位符號，兩語相同',
}

/** 會被念出或顯示的屬性：值含任何字母即違規。 */
const VISIBLE_ATTRS = new Set([
  'aria-label',
  'aria-description',
  'aria-placeholder',
  'aria-roledescription',
  'aria-valuetext',
  'title',
  'placeholder',
  'alt',
  'label',
])

/**
 * 確定不會顯示的屬性（白名單）。不在名單上的屬性——包括自訂元件的 prop——其字串值走 prose 規則；
 * 反過來列黑名單的話，`<Row value="…" />` 這類渲染型 prop 會整個漏掉（T917 複審 finding A）。
 */
const NON_VISIBLE_ATTRS = new Set([
  'className',
  'key',
  'id',
  'type',
  'role',
  'scope',
  'htmlFor',
  'rel',
  'target',
  'href',
  'src',
  'name',
  'method',
  'accept',
  'autoComplete',
  'inputMode',
  'lang',
  'dir',
  'aria-hidden',
  'aria-live',
  'aria-current',
  'aria-pressed',
  'aria-expanded',
  'aria-controls',
  'aria-describedby',
  'aria-labelledby',
  'attribute',
  'defaultTheme',
  'side',
  'align',
])

const KEY_NS = '(?:cbom\\.err|cli|report|crypto|severity|server|console|ui)'
const I18N_KEY = new RegExp(`^${KEY_NS}\\.[a-z0-9_.]+$`)

type Rule = 'jsx-text' | 'jsx-expr' | 'visible-attr' | 'prose' | 'bad-key' | 'emoji'
type Violation = { file: string; line: number; rule: Rule; text: string }

const LETTER = /\p{L}/u
const EMOJI = /\p{Extended_Pictographic}/u
const HAN = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u
const CAPITALIZED_WORD = /(?:^|[^\p{L}\p{N}_$])\p{Lu}/u
const PURE_WORD = /^\p{L}{2,}$/u

function stripExempt(text: string): string {
  let out = text
  for (const tok of Object.keys(EXEMPT_TOKENS)) {
    out = out.split(tok).join(' ')
  }
  return out
}

const pureWords = (s: string) => s.split(/\s+/).filter((w) => PURE_WORD.test(w)).length
const hasLetter = (s: string) => LETTER.test(stripExempt(s))
const looksLikeProse = (s: string, isTemplatePiece: boolean) => {
  const r = stripExempt(s)
  return (
    HAN.test(r) || CAPITALIZED_WORD.test(r) || pureWords(r) >= (isTemplatePiece ? 1 : 2)
  )
}

/** 字面值的文字（含模板字串的固定片段）；非字面值回 null。 */
function literalText(n: ts.Node): string | null {
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text
  if (ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n)) return n.text
  return null
}

const isTemplatePiece = (n: ts.Node) =>
  ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n)

/** 運算式最後會被渲染的字面值葉節點：穿過括號、條件、`??`／`||`／`+`／`&&` 右側、模板字串。 */
function renderLeaves(e: ts.Expression, out: ts.Node[] = []): ts.Node[] {
  if (ts.isParenthesizedExpression(e)) return renderLeaves(e.expression, out)
  if (ts.isConditionalExpression(e)) {
    renderLeaves(e.whenTrue, out)
    return renderLeaves(e.whenFalse, out)
  }
  if (ts.isBinaryExpression(e)) {
    const k = e.operatorToken.kind
    if (
      k === ts.SyntaxKind.QuestionQuestionToken ||
      k === ts.SyntaxKind.BarBarToken ||
      k === ts.SyntaxKind.PlusToken
    ) {
      renderLeaves(e.left, out)
      return renderLeaves(e.right, out)
    }
    // `&&` 左側的非空字串字面值必為真值、不會被渲染
    if (k === ts.SyntaxKind.AmpersandAmpersandToken) return renderLeaves(e.right, out)
    return out
  }
  if (ts.isTemplateExpression(e)) {
    out.push(e.head, ...e.templateSpans.map((s) => s.literal))
    return out
  }
  if (literalText(e) !== null) out.push(e)
  return out
}

const isTCall = (c: ts.CallExpression) => /^(t|i18n\.t)$/.test(c.expression.getText())

/** 往上找最近的 JSX 屬性；遇到 JSX 元素或敘述即停（字面值不在屬性值裡）。 */
function enclosingAttr(n: ts.Node): ts.JsxAttribute | null {
  for (let p = n.parent; p; p = p.parent) {
    if (ts.isJsxAttribute(p)) return p
    if (ts.isJsxElement(p) || ts.isJsxSelfClosingElement(p) || ts.isStatement(p)) return null
  }
  return null
}

/** 該字面值所在位置是否「本來就不是給人看的」（prose 規則的排除清單）。 */
function inSafeContext(n: ts.Node): boolean {
  const p = n.parent
  if (!p) return true
  if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isImportAttribute?.(p))
    return true
  if (ts.isLiteralTypeNode(p) || ts.isCaseClause(p)) return true
  if (ts.isPropertyAssignment(p) && p.name === n) return true
  if (ts.isBinaryExpression(p)) {
    const k = p.operatorToken.kind
    if (
      k === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      k === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      k === ts.SyntaxKind.EqualsEqualsToken ||
      k === ts.SyntaxKind.ExclamationEqualsToken ||
      k === ts.SyntaxKind.InKeyword
    )
      return true
  }
  // t() 的鍵另由 bad-key 規則驗形態
  if (ts.isCallExpression(p) && p.arguments[0] === n && isTCall(p)) return true
  // 開發者訊息（不會出現在畫面上）
  if (ts.isNewExpression(p) && p.expression.getText().endsWith('Error')) return true
  const attr = enclosingAttr(n)
  if (attr && NON_VISIBLE_ATTRS.has(attr.name.getText())) return true
  return false
}

export function scanSource(file: string, src: string): Violation[] {
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  const out: Violation[] = []
  const push = (n: ts.Node, rule: Rule, text: string) => {
    const { line } = sf.getLineAndCharacterOfPosition(n.getStart(sf))
    out.push({ file, line: line + 1, rule, text: text.trim() })
  }
  // 已由 jsx-expr / visible-attr 判過的節點，prose 不重複報
  const judged = new Set<ts.Node>()

  const visit = (n: ts.Node) => {
    if (ts.isJsxText(n)) {
      if (EMOJI.test(n.text)) push(n, 'emoji', n.text)
      else if (hasLetter(n.text)) push(n, 'jsx-text', n.text)
    } else if (ts.isJsxExpression(n) && n.expression) {
      const p = n.parent
      const isChild = ts.isJsxElement(p) || ts.isJsxFragment(p)
      const isVisibleAttr = ts.isJsxAttribute(p) && VISIBLE_ATTRS.has(p.name.getText(sf))
      if (isChild || isVisibleAttr) {
        for (const leaf of renderLeaves(n.expression)) {
          judged.add(leaf)
          const text = literalText(leaf) ?? ''
          if (EMOJI.test(text)) push(leaf, 'emoji', text)
          else if (hasLetter(text)) push(leaf, isChild ? 'jsx-expr' : 'visible-attr', text)
        }
      }
    } else if (
      ts.isJsxAttribute(n) &&
      n.initializer &&
      ts.isStringLiteral(n.initializer) &&
      VISIBLE_ATTRS.has(n.name.getText(sf))
    ) {
      judged.add(n.initializer)
      const text = n.initializer.text
      if (EMOJI.test(text)) push(n, 'emoji', text)
      else if (hasLetter(text)) push(n, 'visible-attr', text)
    } else if (ts.isCallExpression(n) && isTCall(n) && n.arguments[0]) {
      const text = literalText(n.arguments[0])
      if (text !== null && !isTemplatePiece(n.arguments[0]) && !I18N_KEY.test(text)) {
        judged.add(n.arguments[0])
        push(n.arguments[0], 'bad-key', text)
      }
    } else {
      const text = literalText(n)
      if (text !== null && !judged.has(n)) {
        if (EMOJI.test(text)) push(n, 'emoji', text)
        else if (!inSafeContext(n) && looksLikeProse(text, isTemplatePiece(n)))
          push(n, 'prose', text)
      }
    }
    ts.forEachChild(n, visit)
  }
  visit(sf)
  return out
}

function countTCalls(src: string): number {
  const sf = ts.createSourceFile('x.tsx', src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
  let n = 0
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && /^(t|i18n\.t)$/.test(node.expression.getText(sf))) n++
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return n
}

// ── 反空轉哨兵：每條規則、每條分支路徑各一個必紅樣本，外加一份必綠樣本 ──
const MUST_FAIL: [Rule, string, string][] = [
  ['jsx-text', '表頭', `const A = () => <th>Name</th>`],
  ['jsx-text', 'v0.4.0 計數', `const A = () => <span>· {n} components · {m} findings</span>`],
  ['jsx-expr', '條件分支', `const A = ({ x }) => <td>{x ? 'Yes' : t('report.x')}</td>`],
  ['jsx-expr', '?? 分支', `const A = ({ x }) => <td>{x ?? 'none yet'}</td>`],
  ['jsx-expr', '|| 分支', `const A = ({ x }) => <td>{x || 'none'}</td>`],
  ['jsx-expr', '+ 串接', `const A = ({ n }) => <td>{n + ' items'}</td>`],
  ['jsx-expr', '模板字串', 'const A = ({ n }) => <td>{`${n} items`}</td>'],
  ['visible-attr', '字串屬性', `const A = () => <button aria-label="theme" />`],
  ['visible-attr', 'title 屬性', `const A = () => <span title="Details" />`],
  ['visible-attr', '運算式屬性', `const A = () => <button aria-label={'theme'} />`],
  ['visible-attr', '屬性模板字串', 'const A = ({ x }) => <img alt={`photo of ${x}`} />'],
  ['prose', '陣列標籤', `const rows = [['Generated', m.generated_at]]`],
  ['prose', '元件 prop', `const A = () => <Row label={t('report.x')} value="Not configured" />`],
  ['prose', '全小寫片語', `const msg = cond ? 'not configured' : t('report.x')`],
  ['prose', '模板片段（v0.4.0 寫法挪出 JSX）', 'const s = `${a} components · ${b} findings`'],
  ['prose', '中文字面值', `const label = '產生時間'`],
  ['bad-key', '英文當鍵', `const A = () => <p>{t('No data')}</p>`],
  ['bad-key', '中文當鍵', `const A = () => <p>{t('暫無資料')}</p>`],
  ['emoji', 'JSX 文字', `const A = () => <p>⚠️ {t('report.notes.x')}</p>`],
  ['emoji', '運算式', `const A = ({ d }) => <b>{d ? '☀️' : '🌙'}</b>`],
]
const MUST_PASS = `
import { x } from './data'
type S = 'Critical' | 'High'
const A = ({ s, ok, n, c }: { s: S; ok: boolean; n: number; c: string }) => {
  if (s === 'Critical') throw new Error('Unreachable state')
  switch (s) { case 'High': break }
  const next = ok ? 'light' : 'dark'
  return (
    <div className="mx-auto max-w-4xl" role="note" aria-hidden="true">
      <h1>CyTrace — {t('report.title')}</h1>
      <span title={t('ui.language', { lang: 'English' === c ? c : n })}>{n} MB</span>
      <span className={\`rounded border \${ok ? 'text-white dark:bg-gray-900' : 'px-3 py-1'}\`} />
      <tr key={\`\${c}-\${n}\`}><th>{t(\`report.col.\${c}\`)}</th></tr>
      <a href="#/scans/new" aria-current={ok ? 'page' : undefined}>{t(ok ? 'ui.theme_dark' : 'ui.theme_light')}</a>
      {'Failed' in s ? t('report.crypto.failed') : '—'}
    </div>
  )
}
`

function selfTest(): string[] {
  const errs: string[] = []
  for (const [rule, name, src] of MUST_FAIL) {
    const got = scanSource(`<sentinel:${rule}:${name}>`, src)
    if (!got.some((v) => v.rule === rule)) {
      errs.push(`哨兵 ${rule}（${name}）應判違規卻沒有（實得：${JSON.stringify(got)}）`)
    }
  }
  const clean = scanSource('<sentinel:pass>', MUST_PASS)
  if (clean.length) errs.push(`必綠樣本被誤判：${JSON.stringify(clean)}`)
  return errs
}

// ── 主程式 ──
const files: string[] = []
const walk = (d: string) => {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name)
    if (e.isDirectory()) walk(p)
    else if (e.name.endsWith('.tsx')) files.push(p)
  }
}
walk(SRC)

const errors = selfTest()

// 下限貼近實值（2026-10-05：14 個 .tsx、t() 呼叫 116 次），留約三成緩衝供合法刪減
const MIN_FILES = 10
const MIN_T_CALLS = 80
const REQUIRED = ['App.tsx', 'components/ui.tsx', 'console/components/Layout.tsx']
const rel = files.map((f) => path.relative(SRC, f).split(path.sep).join('/'))
for (const r of REQUIRED) {
  if (!rel.includes(r)) errors.push(`必掃檔案 ${r} 不在掃描範圍——glob 或目錄結構已變`)
}
let tCalls = 0
const violations: Violation[] = []
for (const f of files) {
  const src = fs.readFileSync(f, 'utf8')
  tCalls += countTCalls(src)
  violations.push(...scanSource(path.relative(SRC, f), src))
}
if (files.length < MIN_FILES || tCalls < MIN_T_CALLS) {
  errors.push(
    `掃描量低於下限：${files.length} 個 .tsx（下限 ${MIN_FILES}）、t() 呼叫 ${tCalls} 次` +
      `（下限 ${MIN_T_CALLS}）——若為刻意刪減，請下修此處並在 commit 訊息說明`,
  )
}

for (const v of violations) {
  errors.push(`frontend/src/${v.file}:${v.line} [${v.rule}] ${JSON.stringify(v.text)}`)
}

if (errors.length) {
  console.error('✗ 前端硬編碼使用者可見字串檢查失敗：')
  for (const e of errors) console.error('  ' + e)
  console.error('  改用 locales/*.json 的鍵經 t() 輸出；專有名詞與單位才可列入 EXEMPT_TOKENS（附理由）。')
  process.exit(1)
}
console.log(
  `✓ 前端無硬編碼使用者可見字串（${files.length} 個 .tsx、t() 呼叫 ${tCalls} 次；` +
    `${MUST_FAIL.length} 個必紅哨兵涵蓋 6 條規則、必綠樣本為綠）`,
)
