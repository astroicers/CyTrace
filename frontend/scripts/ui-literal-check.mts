/**
 * 前端畫面不得硬編碼使用者可見字串（CLAUDE.md「i18n 雙語強制」；T917）。
 *
 * v0.4.0 的報表裡留著 `Generated`、`Name`／`Version`、`· N components · M findings` 等英文
 * 字面值，中文報表照樣印英文；`scripts/i18n-check.py` 只驗「被引用的鍵存在」，
 * 對「根本沒走 t() 的字串」看不見。本檢查以 TypeScript AST 掃 `frontend/src/**\/*.tsx`：
 *
 * - **jsx-text**：JSX 文字節點含任何字母。
 * - **jsx-expr**：JSX 子節點運算式（含條件／`??`／`||` 分支與模板字串）裡的字串字面值含字母。
 * - **visible-attr**：`aria-label`、`title`、`placeholder`、`alt` 等會被念出或顯示的屬性值含字母。
 * - **prose**：其他位置的字串字面值「像文字」（含中日韓字元，或有大寫開頭的單字）
 *   ——抓 `['Generated', m.generated_at]` 這種先放進陣列、之後才渲染的標籤。
 *   比較運算元、`case`、型別字面值、import、`t()` 的鍵、非可見屬性、`new Error()` 不算。
 * - **emoji**：任何 Extended_Pictographic 字元。交付場域多為無彩色 emoji 字型的離線機器，
 *   ⚠️／🌐／🌙 會變成豆腐字。
 *
 * 專有名詞與單位（產品名、引擎名、`MB`）列在 [`EXEMPT_TOKENS`]，**逐項寫理由**；
 * 從字串移除這些詞之後若仍有字母，照樣判違規。
 *
 * 反空轉：每條規則各有一個必紅樣本、外加一個必綠樣本；另有掃描檔數與 `t()` 呼叫數的下限，
 * 以及必須被掃到的檔案清單——glob 或剖析一旦失效，「零違規」不含資訊。
 *
 * 跑法：node --experimental-strip-types frontend/scripts/ui-literal-check.mts
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

type Rule = 'jsx-text' | 'jsx-expr' | 'visible-attr' | 'prose' | 'emoji'
type Violation = { file: string; line: number; rule: Rule; text: string }

const LETTER = /\p{L}/u
const EMOJI = /\p{Extended_Pictographic}/u
const HAN = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u
const CAPITALIZED_WORD = /(?:^|[^\p{L}\p{N}_$])\p{Lu}/u

function stripExempt(text: string): string {
  let out = text
  for (const tok of Object.keys(EXEMPT_TOKENS)) {
    out = out.split(tok).join(' ')
  }
  return out
}

const hasLetter = (s: string) => LETTER.test(stripExempt(s))
const looksLikeProse = (s: string) => {
  const r = stripExempt(s)
  return HAN.test(r) || CAPITALIZED_WORD.test(r)
}

/** 字面值的文字（含模板字串的固定片段）；非字面值回 null。 */
function literalText(n: ts.Node): string | null {
  if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return n.text
  if (ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n)) return n.text
  return null
}

/** 運算式最後會被渲染的字面值葉節點：穿過括號、條件、`??`／`||`／`&&`、模板字串。 */
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

/** 該字面值所在位置是否「本來就不是給人看的」（prose 規則的排除清單）。 */
function inSafeContext(n: ts.Node): boolean {
  const p = n.parent
  if (!p) return true
  if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isImportAttribute?.(p))
    return true
  if (ts.isLiteralTypeNode(p) || ts.isCaseClause(p)) return true
  if (ts.isJsxAttribute(p)) return true // 可見屬性另由 visible-attr 規則處理
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
  if (ts.isCallExpression(p) && p.arguments[0] === n) {
    const callee = p.expression.getText()
    if (callee === 't' || callee === 'i18n.t') return true
  }
  // 開發者訊息（不會出現在畫面上）
  if (ts.isNewExpression(p) && p.expression.getText().endsWith('Error')) return true
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
      const isVisibleAttr =
        ts.isJsxAttribute(p) && VISIBLE_ATTRS.has(p.name.getText(sf))
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
    } else {
      const text = literalText(n)
      if (text !== null && !judged.has(n)) {
        if (EMOJI.test(text)) push(n, 'emoji', text)
        else if (!inSafeContext(n) && looksLikeProse(text)) push(n, 'prose', text)
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

// ── 反空轉哨兵：每條規則一個必紅樣本，外加一個必綠樣本 ──
const MUST_FAIL: Record<Rule, string> = {
  'jsx-text': `const A = () => <th>Name</th>`,
  'jsx-expr': `const A = ({ x }) => <td>{x ? 'Yes' : t('k')}</td>`,
  'visible-attr': `const A = () => <button aria-label="theme" />`,
  prose: `const rows = [['Generated', m.generated_at]]`,
  emoji: `const A = () => <p>⚠️ {t('report.notes.x')}</p>`,
}
const MUST_PASS = `
import { x } from './data'
type S = 'Critical' | 'High'
const A = ({ s }: { s: S }) => {
  if (s === 'Critical') throw new Error('Unreachable state')
  switch (s) { case 'High': break }
  return (
    <div className="mx-auto" role="note" aria-hidden="true">
      <h1>CyTrace — {t('report.title')}</h1>
      <span title={t('ui.language')}>{n} MB</span>
      {'Failed' in s ? t('report.crypto.failed') : '—'}
    </div>
  )
}
`

function selfTest(): string[] {
  const errs: string[] = []
  for (const [rule, src] of Object.entries(MUST_FAIL) as [Rule, string][]) {
    const got = scanSource(`<sentinel:${rule}>`, src)
    if (!got.some((v) => v.rule === rule)) {
      errs.push(`哨兵 ${rule} 應判違規卻沒有（實得：${JSON.stringify(got)}）`)
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
    `${Object.keys(MUST_FAIL).length} 條規則哨兵皆紅、必綠樣本為綠）`,
)
