import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '../api/client'
import { uploadScan, type UploadHandle } from '../api/upload'
import { ApiError, type VersionInfo } from '../api/types'
import { SEVERITY_ORDER, SEVERITY_KEY } from '../../types'
import { navigate } from '../router'

type Mode = 'upload' | 'path'
const FAIL_ON_VALUES = SEVERITY_ORDER.map((s) => s.toLowerCase())

export function NewScanPage() {
  const { t } = useTranslation()
  const [mode, setMode] = useState<Mode>('upload')
  const [version, setVersion] = useState<VersionInfo | null>(null)
  const [failOn, setFailOn] = useState('')
  const [busy, setBusy] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  // upload 模式
  const [file, setFile] = useState<File | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [progress, setProgress] = useState<number | null>(null)
  const uploadRef = useRef<UploadHandle | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // path 模式
  const [root, setRoot] = useState('')
  const [path, setPath] = useState('')

  useEffect(() => {
    api
      .version()
      .then((v) => {
        setVersion(v)
        if (v.scan_roots.length > 0) setRoot(v.scan_roots[0])
      })
      .catch(() => {})
  }, [])

  const failOnParam = failOn || undefined

  const submitUpload = () => {
    if (!file) {
      setErrorMsg(t('console.scan.error_no_file'))
      return
    }
    setBusy(true)
    setErrorMsg(null)
    setProgress(0)
    const handle = uploadScan(file, failOnParam, setProgress)
    uploadRef.current = handle
    handle.promise
      .then((job) => navigate({ page: 'job', id: job.id }))
      .catch((err) => {
        if (!(err instanceof ApiError && err.code === 'aborted')) {
          setErrorMsg(err instanceof ApiError ? t(err.message) : t('console.common.error'))
        }
        setBusy(false)
        setProgress(null)
      })
  }

  const submitPath = () => {
    if (!path.trim()) {
      setErrorMsg(t('console.scan.error_no_path'))
      return
    }
    setBusy(true)
    setErrorMsg(null)
    api
      .createMountedJob(root, path.trim(), failOnParam)
      .then((job) => navigate({ page: 'job', id: job.id }))
      .catch((err) => {
        setErrorMsg(err instanceof ApiError ? t(err.message) : t('console.common.error'))
        setBusy(false)
      })
  }

  const cancelUpload = () => uploadRef.current?.abort()
  const hasRoots = (version?.scan_roots.length ?? 0) > 0

  return (
    <section className="max-w-xl">
      <h1 className="text-lg font-bold">{t('console.scan.title')}</h1>

      {/* 模式切換 */}
      <div
        role="tablist"
        className="mt-6 inline-flex rounded border border-gray-300 p-0.5 text-sm dark:border-gray-700"
      >
        {(['upload', 'path'] as Mode[]).map((m) => (
          <button
            key={m}
            role="tab"
            aria-selected={mode === m}
            onClick={() => setMode(m)}
            className={`rounded px-3 py-1 ${
              mode === m
                ? 'bg-gray-900 font-semibold text-white dark:bg-gray-100 dark:text-gray-900'
                : 'text-gray-600 dark:text-gray-400'
            }`}
          >
            {t(m === 'upload' ? 'console.scan.mode_upload' : 'console.scan.mode_path')}
          </button>
        ))}
      </div>

      <div className="mt-6 grid gap-5">
        {mode === 'upload' ? (
          <div className="grid gap-2">
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => {
                e.preventDefault()
                setDragOver(true)
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault()
                setDragOver(false)
                if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0])
              }}
              className={`grid place-items-center gap-1 rounded border-2 border-dashed px-4 py-10 text-center text-sm ${
                dragOver
                  ? 'border-sev-low bg-gray-50 dark:bg-gray-900'
                  : 'border-gray-300 dark:border-gray-700'
              }`}
            >
              <span className="font-medium">
                {file ? file.name : t('console.scan.drop_hint')}
              </span>
              <span className="text-xs text-gray-500">
                {t('console.scan.formats_hint')}
              </span>
            </button>
            <input
              ref={fileInputRef}
              type="file"
              className="sr-only"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </div>
        ) : (
          <>
            {!hasRoots && (
              <p className="text-sm text-status-interrupted">
                {t('console.scan.no_roots')}
              </p>
            )}
            <div className="grid gap-2">
              <label htmlFor="root" className="text-sm font-medium">
                {t('console.scan.root_label')}
              </label>
              <select
                id="root"
                value={root}
                disabled={!hasRoots}
                onChange={(e) => setRoot(e.target.value)}
                className="rounded border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-900"
              >
                {version?.scan_roots.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
            <div className="grid gap-2">
              <label htmlFor="path" className="text-sm font-medium">
                {t('console.scan.path_label')}
              </label>
              <input
                id="path"
                type="text"
                value={path}
                disabled={!hasRoots}
                placeholder={t('console.scan.path_placeholder')}
                onChange={(e) => setPath(e.target.value)}
                className="rounded border border-gray-300 bg-white px-3 py-2 font-mono text-sm dark:border-gray-600 dark:bg-gray-900"
              />
            </div>
          </>
        )}

        {/* fail-on 門檻 */}
        <div className="grid gap-2">
          <label htmlFor="failon" className="text-sm font-medium">
            {t('console.scan.fail_on')}
          </label>
          <select
            id="failon"
            value={failOn}
            onChange={(e) => setFailOn(e.target.value)}
            className="rounded border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-900"
          >
            <option value="">{t('console.scan.fail_on_none')}</option>
            {FAIL_ON_VALUES.map((v, i) => (
              <option key={v} value={v}>
                {t(SEVERITY_KEY[SEVERITY_ORDER[i]])}
              </option>
            ))}
          </select>
        </div>

        {errorMsg && (
          <p role="alert" className="text-sm text-sev-critical">
            {errorMsg}
          </p>
        )}

        {progress !== null && (
          <div className="grid gap-1">
            <div
              role="progressbar"
              aria-valuenow={progress}
              aria-valuemin={0}
              aria-valuemax={100}
              className="h-2 overflow-hidden rounded bg-gray-200 dark:bg-gray-800"
            >
              <div
                className="h-full bg-sev-low transition-[width]"
                style={{ width: `${progress}%` }}
              />
            </div>
            <span className="text-xs text-gray-500">
              {t('console.scan.uploading', { percent: progress })}
            </span>
          </div>
        )}

        <div className="flex gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={mode === 'upload' ? submitUpload : submitPath}
            className="rounded bg-gray-900 px-4 py-2 text-sm font-semibold text-white transition active:translate-y-px hover:bg-gray-800 disabled:opacity-50 dark:bg-gray-100 dark:text-gray-900 dark:hover:bg-white"
          >
            {busy ? t('console.scan.submitting') : t('console.scan.submit')}
          </button>
          {progress !== null && (
            <button
              type="button"
              onClick={cancelUpload}
              className="rounded border border-gray-300 px-4 py-2 text-sm hover:bg-gray-100 dark:border-gray-600 dark:hover:bg-gray-800"
            >
              {t('console.scan.cancel')}
            </button>
          )}
        </div>
      </div>
    </section>
  )
}
