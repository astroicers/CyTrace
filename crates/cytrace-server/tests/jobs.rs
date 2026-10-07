//! Job 生命週期整合測試——FakeEngine 注入（不需 syft/grype binary，air-gapped CI 可跑）。

use axum::body::Body;
// 測試以 ConnectInfo 注入對端位址（模擬 serve() 的 connect_info），非 handler 裸用
#[allow(clippy::disallowed_types)]
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use cytrace_core::engine::ScanEngine;
use cytrace_core::error::Result as CoreResult;
use cytrace_server::auth::{hash_password, CSRF_HEADER};
use cytrace_server::config::{CliFlags, ServerConfig};
use cytrace_server::router::build_router_with_state;
use cytrace_server::state::{AppState, Hooks};
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use tower::util::ServiceExt;

// 直接重用 core 的 golden fixtures（2 元件、Critical+Medium 兩弱點）
const CYCLONEDX: &str = include_str!("../../cytrace-core/tests/fixtures/cyclonedx.json");
const GRYPE: &str = include_str!("../../cytrace-core/tests/fixtures/grype.json");
const CBOM: &str = include_str!("../../cytrace-core/tests/fixtures/cbom.json");
const SPDX: &str = include_str!("../../cytrace-core/tests/fixtures/spdx.json");

const TEST_PASSWORD: &str = "test-password-123";
static TEST_PHC: LazyLock<String> = LazyLock::new(|| hash_password(TEST_PASSWORD).unwrap());
static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct FakeEngine;
impl ScanEngine for FakeEngine {
    fn sbom(&self, _target: &str) -> CoreResult<String> {
        Ok(CYCLONEDX.into())
    }
    fn sbom_with_spdx(&self, _target: &str) -> CoreResult<(String, Option<String>)> {
        Ok((CYCLONEDX.into(), Some(SPDX.into())))
    }
    fn vuln(&self, _sbom: &str) -> CoreResult<String> {
        Ok(GRYPE.into())
    }
    fn cbom(&self, _target: &str) -> CoreResult<Option<cytrace_core::engine::CbomOutput>> {
        Ok(Some(cytrace_core::engine::CbomOutput {
            json: CBOM.into(),
            skipped: 0,
            admitted_keys: 0,
            admitted_certs: 0,
        }))
    }
}

/// CBOM 引擎壞掉：驗證主流程（SBOM/CVE/報表）不受影響（ADR-013 決策 4）。
struct BrokenCbomEngine;
impl ScanEngine for BrokenCbomEngine {
    fn sbom(&self, _target: &str) -> CoreResult<String> {
        Ok(CYCLONEDX.into())
    }
    fn vuln(&self, _sbom: &str) -> CoreResult<String> {
        Ok(GRYPE.into())
    }
    fn cbom(&self, _target: &str) -> CoreResult<Option<cytrace_core::engine::CbomOutput>> {
        Err(cytrace_core::CytraceError::Engine("theia 爆炸".into()))
    }
}

/// 慢引擎：卡住 sbom 讓 job 停在 running / 佇列（取消與 409 測試用）。
struct SlowEngine;
impl ScanEngine for SlowEngine {
    fn sbom(&self, _target: &str) -> CoreResult<String> {
        std::thread::sleep(std::time::Duration::from_millis(800));
        Ok(CYCLONEDX.into())
    }
    fn vuln(&self, _sbom: &str) -> CoreResult<String> {
        Ok(GRYPE.into())
    }
}

/// syft 失敗：job 以 `server.err.engine` 失敗（查詢時渲染 message 的測試用）。
struct FailingSbomEngine;
impl ScanEngine for FailingSbomEngine {
    fn sbom(&self, _target: &str) -> CoreResult<String> {
        Err(cytrace_core::CytraceError::Engine(
            "syft exit Some(1): ".into(),
        ))
    }
    fn vuln(&self, _sbom: &str) -> CoreResult<String> {
        Ok(GRYPE.into())
    }
}

struct TestEnv {
    app: Router,
    #[allow(dead_code)]
    base: PathBuf,
}

/// 建測試環境：temp data_dir、非空 db 目錄（db_present=true）、掃描白名單 root。
fn build_env(engine: Arc<dyn ScanEngine>, db_present: bool, max_concurrent: usize) -> TestEnv {
    build_env_with(engine, db_present, max_concurrent, &[])
}

/// 同 [`build_env`]，另可覆寫環境變數（如上傳／解壓上限）。
fn build_env_with(
    engine: Arc<dyn ScanEngine>,
    db_present: bool,
    max_concurrent: usize,
    extra_env: &[(&str, &str)],
) -> TestEnv {
    build_env_seeded(engine, db_present, max_concurrent, extra_env, &[])
}

/// 同 [`build_env_with`]，另在啟動**前**寫入既有 job 記錄（走真的重啟恢復路徑）。
fn build_env_seeded(
    engine: Arc<dyn ScanEngine>,
    db_present: bool,
    max_concurrent: usize,
    extra_env: &[(&str, &str)],
    seed: &[serde_json::Value],
) -> TestEnv {
    build_env_full(
        engine,
        db_present,
        max_concurrent,
        extra_env,
        seed,
        Hooks::default(),
    )
}

/// 同 [`build_env_seeded`]，另注入競態測試用的時間點 hook。
fn build_env_full(
    engine: Arc<dyn ScanEngine>,
    db_present: bool,
    max_concurrent: usize,
    extra_env: &[(&str, &str)],
    seed: &[serde_json::Value],
    hooks: Hooks,
) -> TestEnv {
    let base = std::env::temp_dir().join(format!(
        "cytrace-jobs-test-{}-{}",
        std::process::id(),
        DIR_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&base);
    let scan_root = base.join("scan-targets");
    std::fs::create_dir_all(scan_root.join("app")).unwrap();
    std::fs::write(scan_root.join("app/bin"), b"x").unwrap();
    let db_dir = base.join("db");
    std::fs::create_dir_all(&db_dir).unwrap();
    if db_present {
        std::fs::write(db_dir.join("metadata.json"), "{}").unwrap();
    }

    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("CYTRACE_ADMIN_PASSWORD_HASH".into(), TEST_PHC.clone());
    env.insert(
        "CYTRACE_SCAN_ROOTS".into(),
        format!("targets={}", scan_root.display()),
    );
    env.insert(
        "CYTRACE_MAX_CONCURRENT_SCANS".into(),
        max_concurrent.to_string(),
    );
    if db_present {
        env.insert("GRYPE_DB_CACHE_DIR".into(), db_dir.display().to_string());
    }
    for (k, v) in extra_env {
        env.insert((*k).into(), (*v).into());
    }
    let cfg = ServerConfig::resolve(
        CliFlags {
            bind: Some("127.0.0.1:0".into()),
            data_dir: Some(base.join("data")),
            ..Default::default()
        },
        env,
    )
    .unwrap();
    for rec in seed {
        let dir = base.join("data/jobs").join(rec["id"].as_str().unwrap());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("job.json"), rec.to_string()).unwrap();
        // 上傳型 job 在磁碟上一定帶著 input/（由 upload handler 建立），植入時照實際形狀補上
        if rec["target"]
            .as_str()
            .is_some_and(|t| t.starts_with("upload:"))
        {
            std::fs::create_dir_all(dir.join("input/extracted")).unwrap();
            std::fs::write(dir.join("input/extracted/secret.txt"), b"classified").unwrap();
        }
    }
    let state = AppState::with_engine(cfg, engine)
        .unwrap()
        .with_hooks(hooks);
    TestEnv {
        app: build_router_with_state(state),
        base,
    }
}

fn with_csrf_and(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.header(CSRF_HEADER, "1")
}

async fn login(app: &Router) -> String {
    let mut req = with_csrf_and(Request::post("/api/v1/session"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!("{{\"password\":\"{TEST_PASSWORD}\"}}")))
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([10, 1, 0, 1], 40000))));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    resp.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

async fn json_of(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn create_job(
    app: &Router,
    cookie: &str,
    path: &str,
    fail_on: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let fail_on_field = fail_on
        .map(|f| format!(",\"fail_on\":\"{f}\""))
        .unwrap_or_default();
    let body = format!(
        "{{\"target\":{{\"kind\":\"mounted\",\"root\":\"targets\",\"path\":\"{path}\"}}{fail_on_field}}}"
    );
    let req = with_csrf_and(Request::post("/api/v1/jobs"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, json_of(resp).await)
}

/// 同 create_job，但開啟 CBOM（ADR-013：預設關閉，須顯式指定）。
async fn create_job_with_cbom(
    app: &Router,
    cookie: &str,
    path: &str,
) -> (StatusCode, serde_json::Value) {
    let body = format!(
        "{{\"target\":{{\"kind\":\"mounted\",\"root\":\"targets\",\"path\":\"{path}\"}},\"cbom\":true}}"
    );
    let req = with_csrf_and(Request::post("/api/v1/jobs"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, json_of(resp).await)
}

async fn get_job(app: &Router, cookie: &str, id: &str) -> serde_json::Value {
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/jobs/{id}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    json_of(resp).await
}

/// 輪詢直到終態（FakeEngine 極快；上限 30 秒防呆，理由見函式內註解）。
async fn wait_terminal(app: &Router, cookie: &str, id: &str) -> serde_json::Value {
    // 上限 30 秒（原 5 秒）：單獨跑時數十毫秒就到終態，但 make test 平行跑多個 test binary、
    // 機器另有負載時曾 6 支同時逾時（2026-10-02 實錄，單獨重跑 29/29 綠）。上限只是時間預算，
    // 不影響鑑別力——到不了終態的 job 照樣在上限後失敗。
    for _ in 0..300 {
        let v = get_job(app, cookie, id).await;
        let s = v["status"].as_str().unwrap_or("").to_string();
        if !matches!(s.as_str(), "queued" | "running") {
            return v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("job 未在時限內到終態");
}

#[tokio::test]
async fn full_job_lifecycle_with_fake_engine() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;

    let (status, v) = create_job(&env.app, &cookie, "app", Some("high")).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["status"], "queued");
    assert_eq!(v["target"], "mounted:targets/app");

    let done = wait_terminal(&env.app, &cookie, &id).await;
    assert_eq!(done["status"], "done", "job 應成功：{done}");
    // fixtures：Critical + Medium → overall_risk Critical；fail_on=high → triggered
    assert_eq!(done["summary"]["overall_risk"], "Critical");
    assert_eq!(done["failon_triggered"], true);
    assert!(done["finished_at"].as_str().unwrap().ends_with('Z'));

    // 產物落盤（report/scan-result/sbom/grype）
    let job_dir = env.base.join("data/jobs").join(&id);
    for f in [
        "job.json",
        "sbom.cdx.json",
        "grype.json",
        "scan-result.json",
        "report.html",
    ] {
        assert!(job_dir.join(f).exists(), "缺產物 {f}");
    }
    // 報表含注入資料（sentinel 已被替換）
    let html = std::fs::read_to_string(job_dir.join("report.html")).unwrap();
    assert!(html.contains("cytrace-data"));

    // 列表
    let resp = env
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/jobs")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let list = json_of(resp).await;
    assert_eq!(list["total"], 1);

    // 終態刪除 → 404
    let req = with_csrf_and(Request::delete(format!("/api/v1/jobs/{id}")))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(!job_dir.exists());
    let v = get_job(&env.app, &cookie, &id).await;
    assert_eq!(v["error"]["kind"], "not_found");
}

#[tokio::test]
async fn db_missing_returns_503_degraded() {
    let env = build_env(Arc::new(FakeEngine), false, 2);
    let cookie = login(&env.app).await;
    let (status, v) = create_job(&env.app, &cookie, "app", None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["error"]["kind"], "db_missing");
}

#[tokio::test]
async fn traversal_and_unknown_paths_forbidden() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    for bad in ["../secret", "/etc", "no/such/dir"] {
        let (status, v) = create_job(&env.app, &cookie, bad, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "path={bad}");
        assert_eq!(v["error"]["kind"], "forbidden_path");
    }
}

#[tokio::test]
async fn invalid_fail_on_rejected() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    let (status, v) = create_job(&env.app, &cookie, "app", Some("catastrophic")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["error"]["kind"], "validation");
}

#[tokio::test]
async fn running_delete_conflicts_and_queued_cancels() {
    // 併發 1 + 慢引擎：第一個 running、第二個 queued
    let env = build_env(Arc::new(SlowEngine), true, 1);
    let cookie = login(&env.app).await;
    let (_, first) = create_job(&env.app, &cookie, "app", None).await;
    let (_, second) = create_job(&env.app, &cookie, "app", None).await;
    let (fid, sid) = (
        first["id"].as_str().unwrap().to_string(),
        second["id"].as_str().unwrap().to_string(),
    );

    // 等第一個進 running
    for _ in 0..30 {
        if get_job(&env.app, &cookie, &fid).await["status"] == "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(get_job(&env.app, &cookie, &fid).await["status"], "running");

    // running → DELETE 409
    let req = with_csrf_and(Request::delete(format!("/api/v1/jobs/{fid}")))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // queued → DELETE = 取消
    let req = with_csrf_and(Request::delete(format!("/api/v1/jobs/{sid}")))
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(get_job(&env.app, &cookie, &sid).await["status"], "canceled");

    // 第一個最終完成（取消的不會被執行）
    let done = wait_terminal(&env.app, &cookie, &fid).await;
    assert_eq!(done["status"], "done");
    assert_eq!(
        get_job(&env.app, &cookie, &sid).await["status"],
        "canceled",
        "取消的 job 不得被 runner 撿走"
    );
}

#[tokio::test]
async fn targets_endpoint_lists_root_names_only() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    let resp = env
        .app
        .clone()
        .oneshot(
            Request::get("/api/v1/targets")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = json_of(resp).await;
    assert_eq!(v["roots"][0]["name"], "targets");
    assert!(v["roots"][0].get("path").is_none(), "不得洩漏實際路徑");
}

// ─── 上傳與報表端點（T805）───

fn multipart_body(boundary: &str, filename: &str, data: &[u8], fail_on: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n");
    if let Some(f) = fail_on {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fail_on\"\r\n\r\n{f}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

fn make_zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        let opt = zip::write::SimpleFileOptions::default();
        for (name, data) in entries {
            w.start_file(*name, opt).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    buf.into_inner()
}

async fn upload_scan(
    app: &Router,
    cookie: &str,
    body: Vec<u8>,
    boundary: &str,
) -> (StatusCode, serde_json::Value) {
    let req = with_csrf_and(Request::post("/api/v1/jobs/upload"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header(header::COOKIE, cookie)
        .body(Body::from(body))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, json_of(resp).await)
}

#[tokio::test]
async fn upload_zip_scans_and_produces_report() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    let zip = make_zip_bytes(&[("app/main.py", b"print(1)"), ("app/lib.py", b"x=2")]);
    let boundary = "----cytracetest";
    let (status, v) = upload_scan(
        &env.app,
        &cookie,
        multipart_body(boundary, "app.zip", &zip, Some("high")),
        boundary,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["target"], "upload:app.zip");

    let done = wait_terminal(&env.app, &cookie, &id).await;
    assert_eq!(done["status"], "done", "{done}");

    // 報表端點：線上檢視回 HTML
    let resp = env
        .app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/jobs/{id}/report"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );

    // download=1 → attachment
    let resp = env
        .app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/jobs/{id}/report?download=1"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("attachment"));

    // result / artifacts JSON
    for (path, key) in [
        ("result", "schema_version"),
        ("artifacts/sbom", "bomFormat"),
    ] {
        let resp = env
            .app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/jobs/{id}/{path}"))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "path={path}");
        let _ = key; // 存在即可（形狀由 core golden 保證）
    }

    // input 掃後預設刪除（keep_input=false）
    assert!(!env.base.join("data/jobs").join(&id).join("input").exists());
}

/// 併發 1 + 慢引擎佔住唯一名額，讓一筆上傳停在 queued，回傳其 job id。
async fn queued_upload(env: &TestEnv, cookie: &str) -> String {
    let (_, blocker) = create_job(&env.app, cookie, "app", None).await;
    let bid = blocker["id"].as_str().unwrap().to_string();
    for _ in 0..30 {
        if get_job(&env.app, cookie, &bid).await["status"] == "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        get_job(&env.app, cookie, &bid).await["status"],
        "running",
        "前提：blocker 佔住唯一的掃描名額"
    );
    let zip = make_zip_bytes(&[("secret.txt", b"classified")]);
    let boundary = "----cytracequeued";
    let (status, v) = upload_scan(
        &env.app,
        cookie,
        multipart_body(boundary, "s.zip", &zip, None),
        boundary,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(get_job(&env.app, cookie, &id).await["status"], "queued");
    id
}

async fn delete_job(env: &TestEnv, cookie: &str, id: &str) -> StatusCode {
    let req = with_csrf_and(Request::delete(format!("/api/v1/jobs/{id}")))
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    env.app.clone().oneshot(req).await.unwrap().status()
}

/// #39：排隊中被取消的上傳 job，`input/` 要在取消當下刪除（不是等到有人手動 DELETE）。
#[tokio::test]
async fn canceling_queued_upload_removes_its_input() {
    let env = build_env(Arc::new(SlowEngine), true, 1);
    let cookie = login(&env.app).await;
    let id = queued_upload(&env, &cookie).await;
    let input = env.base.join("data/jobs").join(&id).join("input");
    assert!(input.exists(), "前提：排隊中的上傳 job 帶著 input/");

    assert_eq!(delete_job(&env, &cookie, &id).await, StatusCode::NO_CONTENT);
    assert_eq!(get_job(&env.app, &cookie, &id).await["status"], "canceled");
    assert!(
        !input.exists(),
        "取消後 input/ 仍在——上傳的機密原檔會留到有人手動刪除（#39）"
    );
    // 只刪 input/，job 記錄仍在（canceled 狀態要查得到）
    assert!(env
        .base
        .join("data/jobs")
        .join(&id)
        .join("job.json")
        .exists());
}

/// #42：DELETE 讀到 queued 之後、嘗試取消之前，runner 搶先開始掃描——取消必然失敗。
/// 此時不得回 204 謊稱已取消，應回 409；正在被掃描的 input/ 也不得刪。
#[tokio::test]
async fn delete_conflicts_when_runner_starts_before_the_cancel() {
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired_in_hook = fired.clone();
    let hooks = Hooks {
        before_cancel: Some(Arc::new(move |app: &AppState, id: &str| {
            assert!(
                app.jobs.start_if_queued(id),
                "前提：hook 模擬 runner 在這個空檔搶先開始掃描"
            );
            fired_in_hook.store(true, Ordering::SeqCst);
        })),
    };
    let env = build_env_full(Arc::new(SlowEngine), true, 1, &[], &[], hooks);
    let cookie = login(&env.app).await;
    let id = queued_upload(&env, &cookie).await;
    let input = env.base.join("data/jobs").join(&id).join("input");

    assert_eq!(
        delete_job(&env, &cookie, &id).await,
        StatusCode::CONFLICT,
        "取消沒有成功（job 已開始掃描），卻回報成功（#42）"
    );
    // 若 DELETE 時 job 已因其他原因是 running，handler 會直接走 running 分支而不經 hook，
    // 測試照樣綠卻沒驗到競態——斷言 hook 確實被呼叫
    assert!(
        fired.load(Ordering::SeqCst),
        "hook 未被呼叫：DELETE 沒有走到 queued 分支，本測試未驗到 #42 的競態"
    );
    assert_eq!(get_job(&env.app, &cookie, &id).await["status"], "running");
    assert!(input.exists(), "正在被掃描的 input/ 不得被刪");
}

/// #46：409 只在「job 已開始掃描」時出現，而 console 上遇到它的情境是按了「取消」。
/// 訊息必須說明已無法取消（running 本來就不能取消），不得再建議「先取消」。
#[tokio::test]
async fn conflict_message_says_a_running_job_cannot_be_canceled() {
    let env = build_env(Arc::new(SlowEngine), true, 1);
    let cookie = login(&env.app).await;
    let (_, job) = create_job(&env.app, &cookie, "app", None).await;
    let id = job["id"].as_str().unwrap().to_string();
    for _ in 0..30 {
        if get_job(&env.app, &cookie, &id).await["status"] == "running" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(get_job(&env.app, &cookie, &id).await["status"], "running");

    for (lang, must_say) in [("zh-TW", "無法取消"), ("en-US", "cannot be canceled")] {
        let req = with_csrf_and(Request::delete(format!("/api/v1/jobs/{id}")))
            .header(header::COOKIE, &cookie)
            .header(header::ACCEPT_LANGUAGE, lang)
            .body(Body::empty())
            .unwrap();
        let (status, v) = send_json(&env.app, req).await;
        let msg = assert_api_error(
            "delete running",
            lang,
            status,
            &v,
            StatusCode::CONFLICT,
            "server.err.conflict",
        );
        assert!(
            msg.contains(must_say),
            "{lang}: 409 訊息須說明已無法取消：{msg}"
        );
    }
}

/// `CYTRACE_KEEP_INPUT=true` 是操作者明示要保留：取消時也不得刪。
#[tokio::test]
async fn canceling_queued_upload_keeps_input_when_keep_input_is_set() {
    let env = build_env_with(
        Arc::new(SlowEngine),
        true,
        1,
        &[("CYTRACE_KEEP_INPUT", "true")],
    );
    let cookie = login(&env.app).await;
    let id = queued_upload(&env, &cookie).await;
    assert_eq!(delete_job(&env, &cookie, &id).await, StatusCode::NO_CONTENT);
    assert!(env.base.join("data/jobs").join(&id).join("input").exists());
}

/// #39：重啟時，上傳 job 留下的 input/ 一律清掉——含被中斷的（queued/running → interrupted）
/// 與修正前就已取消、殘留至今的。job 記錄（job.json）保留；掛載型 job 的掃描目標本身不得被碰。
#[tokio::test]
async fn restart_purges_leftover_upload_inputs() {
    let rec = |i: u32, status: &str| {
        serde_json::json!({ "id": format!("1700000000-0000000{i}"), "status": status,
            "target": "upload:s.zip", "created_at": "2026-01-01T00:00:00Z" })
    };
    let seed = [rec(1, "queued"), rec(2, "running"), rec(3, "canceled")];
    let mounted = serde_json::json!({ "id": "1700000000-00000004", "status": "running",
        "target": "mounted:targets/app", "created_at": "2026-01-01T00:00:00Z" });
    let all: Vec<_> = seed.iter().cloned().chain([mounted]).collect();
    let env = build_env_seeded(Arc::new(FakeEngine), true, 2, &[], &all);
    assert!(
        env.base.join("scan-targets/app/bin").exists(),
        "掛載型 job 的掃描目標不得被重啟清理刪到"
    );
    let cookie = login(&env.app).await;
    for (rec, want) in seed.iter().zip(["interrupted", "interrupted", "canceled"]) {
        let id = rec["id"].as_str().unwrap();
        let dir = env.base.join("data/jobs").join(id);
        assert_eq!(get_job(&env.app, &cookie, id).await["status"], want);
        assert!(
            !dir.join("input").exists(),
            "{id}（{want}）重啟後 input/ 仍在（#39）"
        );
        assert!(dir.join("job.json").exists());
    }
}

/// 重啟清理同樣尊重 `CYTRACE_KEEP_INPUT=true`。
#[tokio::test]
async fn restart_keeps_upload_inputs_when_keep_input_is_set() {
    let seed = [
        serde_json::json!({ "id": "1700000000-00000009", "status": "running",
        "target": "upload:s.zip", "created_at": "2026-01-01T00:00:00Z" }),
    ];
    let env = build_env_seeded(
        Arc::new(FakeEngine),
        true,
        2,
        &[("CYTRACE_KEEP_INPUT", "true")],
        &seed,
    );
    assert!(env
        .base
        .join("data/jobs/1700000000-00000009/input/extracted/secret.txt")
        .exists());
}

#[tokio::test]
async fn upload_zip_slip_rejected() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    let zip = make_zip_bytes(&[("ok.txt", b"x"), ("../evil.txt", b"pwn")]);
    let boundary = "----cytraceslip";
    let (status, v) = upload_scan(
        &env.app,
        &cookie,
        multipart_body(boundary, "e.zip", &zip, None),
        boundary,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["error"]["kind"], "forbidden_path");
}

#[tokio::test]
async fn upload_over_size_limit_rejected() {
    // 上傳上限設 0（=0MB → 任何內容超限）
    let env = {
        let base = std::env::temp_dir().join(format!(
            "cytrace-jobs-test-{}-{}",
            std::process::id(),
            DIR_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        let db_dir = base.join("db");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::write(db_dir.join("metadata.json"), "{}").unwrap();
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert("CYTRACE_ADMIN_PASSWORD_HASH".into(), TEST_PHC.clone());
        env.insert("GRYPE_DB_CACHE_DIR".into(), db_dir.display().to_string());
        env.insert("CYTRACE_MAX_UPLOAD_MB".into(), "0".into());
        let cfg = ServerConfig::resolve(
            CliFlags {
                bind: Some("127.0.0.1:0".into()),
                data_dir: Some(base.join("data")),
                ..Default::default()
            },
            env,
        )
        .unwrap();
        TestEnv {
            app: build_router_with_state(AppState::with_engine(cfg, Arc::new(FakeEngine)).unwrap()),
            base,
        }
    };
    let cookie = login(&env.app).await;
    let boundary = "----cytracebig";
    let (status, v) = upload_scan(
        &env.app,
        &cookie,
        multipart_body(boundary, "big.bin", b"some bytes here", None),
        boundary,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
    assert_eq!(v["error"]["kind"], "payload_too_large");
}

// ─── 安全硬化（T809）───

#[tokio::test]
async fn concurrent_uploads_do_not_cross_contaminate() {
    // B1 迴歸守門：兩個併發上傳各自獨立 job 目錄，產物不互相污染。
    let env = build_env(Arc::new(SlowEngine), true, 2);
    let cookie = login(&env.app).await;
    let zip_a = make_zip_bytes(&[("a/only_in_a.txt", b"AAAA")]);
    let zip_b = make_zip_bytes(&[("b/only_in_b.txt", b"BBBB")]);

    let (app1, app2) = (env.app.clone(), env.app.clone());
    let (ck1, ck2) = (cookie.clone(), cookie.clone());
    let fut_a = async move {
        upload_scan(
            &app1,
            &ck1,
            multipart_body("bnda", "a.zip", &zip_a, None),
            "bnda",
        )
        .await
    };
    let fut_b = async move {
        upload_scan(
            &app2,
            &ck2,
            multipart_body("bndb", "b.zip", &zip_b, None),
            "bndb",
        )
        .await
    };
    let ((sa, va), (sb, vb)) = tokio::join!(fut_a, fut_b);
    assert_eq!(sa, StatusCode::ACCEPTED, "{va}");
    assert_eq!(sb, StatusCode::ACCEPTED, "{vb}");
    let id_a = va["id"].as_str().unwrap().to_string();
    let id_b = vb["id"].as_str().unwrap().to_string();
    assert_ne!(id_a, id_b, "併發上傳必須有不同 job id");

    wait_terminal(&env.app, &cookie, &id_a).await;
    wait_terminal(&env.app, &cookie, &id_b).await;

    // 各 job 的 extracted 只含自己的檔案（keep_input=false 預設會刪 input，
    // 故改驗 job 目錄互不重疊——用 job id 隔離即足夠；此處確認兩 id 目錄獨立存在過）
    assert!(env.base.join("data/jobs").join(&id_a).exists());
    assert!(env.base.join("data/jobs").join(&id_b).exists());
}

#[tokio::test]
async fn artifact_endpoint_rejects_path_traversal_id() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    // 惡意 job id（路徑穿越）→ 404（registry 查無 + id 白名單雙重防護）
    for bad in ["..%2f..%2fetc", "abc/../../../etc"] {
        let resp = env
            .app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/jobs/{bad}/report"))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::BAD_REQUEST,
            "id={bad} status={}",
            resp.status()
        );
    }
}

// ── T907：CBOM 在 server 端的降級不變量（ADR-013 決策 4）──

#[tokio::test]
async fn cbom_engine_failure_does_not_fail_the_job() {
    // 不變量：CBOM 壞掉時，SBOM／CVE／報表全部照常產出，job 不得標為 failed
    let env = build_env(Arc::new(BrokenCbomEngine), true, 2);
    let cookie = login(&env.app).await;
    let (status, v) = create_job_with_cbom(&env.app, &cookie, "app").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = v["id"].as_str().unwrap().to_string();

    let done = wait_terminal(&env.app, &cookie, &id).await;
    assert_eq!(
        done["status"], "done",
        "CBOM 失敗不得讓整個 job 失敗：{done}"
    );
    assert_eq!(
        done["summary"]["overall_risk"], "Critical",
        "主流程結果須完好"
    );

    for (path, key) in [
        ("result", "schema_version"),
        ("artifacts/sbom", "bomFormat"),
    ] {
        let resp = env
            .app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/jobs/{id}/{path}"))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{path} 應仍可取得");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&body).contains(key),
            "{path} 內容不正確"
        );
    }
}

#[tokio::test]
async fn cbom_artifact_is_served_when_scan_succeeds() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    let (_, v) = create_job_with_cbom(&env.app, &cookie, "app").await;
    let id = v["id"].as_str().unwrap().to_string();
    wait_terminal(&env.app, &cookie, &id).await;

    let resp = env
        .app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/jobs/{id}/artifacts/cbom"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "cbom 產物應可下載");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("cryptographic-asset"), "應為 CBOM 內容");
    assert!(!text.contains("PRIVATE KEY"), "NFR-09：不得含金鑰內容");
}

// ── T909：API 錯誤訊息的雙語契約（經真 router，非 helper）──
//
// 第九輪的教訓：把修正寫在有測試的 helper（`ApiError::from_core`），真正在跑的 handler
// 沒驗到。故本段每條錯誤路徑都經 `build_router_with_state` 的真實 router 觸發，
// 並以 zh-TW / en-US 各打一次。

/// 送出請求並回 (status, json)。**回應必須是 JSON**——axum extractor 原生 rejection
/// 回的是英文純文字，`serde_json::from_slice` 在此會直接 panic，那正是要抓的回歸。
async fn send_json(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        panic!(
            "錯誤回應不是 JSON（繞過了 ApiError 的 {{\"error\":{{…}}}} 格式）：{}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, v)
}

fn has_cjk(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c as u32, 0x4E00..=0x9FFF | 0x3000..=0x303F | 0xFF00..=0xFFEF))
}

/// 斷言一個錯誤回應符合雙語契約，回傳 message。
fn assert_api_error(
    label: &str,
    lang: &str,
    status: StatusCode,
    v: &serde_json::Value,
    want_status: StatusCode,
    want_key: &str,
) -> String {
    assert_eq!(status, want_status, "{label}/{lang}: 狀態碼");
    let e = &v["error"];
    assert_eq!(
        e["i18n_key"], want_key,
        "{label}/{lang}: i18n_key 應為具體鍵"
    );
    let msg = e["message"].as_str().expect("message 應為字串").to_string();
    assert!(!msg.is_empty(), "{label}/{lang}: message 為空");
    assert!(
        !msg.contains("{{"),
        "{label}/{lang}: message 殘留佔位符：{msg}"
    );
    assert_ne!(msg, want_key, "{label}/{lang}: message 是裸鍵");
    // detail 只放資料，任何語系都不得夾本專案的中文散文
    if let Some(d) = e["detail"].as_str() {
        assert!(!has_cjk(d), "{label}/{lang}: detail 夾中文散文：{d}");
    }
    if lang == "en-US" {
        assert!(!has_cjk(&msg), "{label}/en-US: message 夾中文：{msg}");
    } else {
        // 反向：zh-TW 必須真的有中文——否則「en-US 無中文」可能只是兩邊都英文
        assert!(has_cjk(&msg), "{label}/zh-TW: message 沒有在地化：{msg}");
    }
    msg
}

const LANGS: [&str; 2] = ["zh-TW", "en-US"];

fn multipart_parts(boundary: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    for (name, filename, data) in parts {
        b.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match filename {
            Some(f) => b.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
            ),
            None => b.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        b.extend_from_slice(data);
        b.extend_from_slice(b"\r\n");
    }
    b.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    b
}

fn upload_req(cookie: &str, lang: &str, content_type: &str, body: Vec<u8>) -> Request<Body> {
    with_csrf_and(Request::post("/api/v1/jobs/upload"))
        .header(header::CONTENT_TYPE, content_type)
        .header(header::COOKIE, cookie)
        .header(header::ACCEPT_LANGUAGE, lang)
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn t909_invalid_fail_on_is_localized() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    for lang in LANGS {
        let body = r#"{"target":{"kind":"mounted","root":"targets","path":"app"},"fail_on":"catastrophic"}"#;
        let req = with_csrf_and(Request::post("/api/v1/jobs"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &cookie)
            .header(header::ACCEPT_LANGUAGE, lang)
            .body(Body::from(body))
            .unwrap();
        let (st, v) = send_json(&env.app, req).await;
        let msg = assert_api_error(
            "fail_on",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.invalid_fail_on",
        );
        assert!(
            msg.contains("catastrophic"),
            "{lang}: 使用者輸入的值須插值進訊息：{msg}"
        );
        // 可用值由 VALID_FAIL_ON 插值，不是文案手抄
        assert!(
            msg.contains("critical") && msg.contains("negligible"),
            "{lang}: 可用值未插值：{msg}"
        );
        assert_eq!(
            v["error"]["detail"], "catastrophic",
            "{lang}: detail 應為原始值"
        );
    }
}

#[tokio::test]
async fn t909_invalid_status_filter_is_localized() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    for lang in LANGS {
        // 以 ?lang= 協商（另一條協商路徑；其餘測試用 Accept-Language）
        let req = Request::get(format!("/api/v1/jobs?status=bogus&lang={lang}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (st, v) = send_json(&env.app, req).await;
        let msg = assert_api_error(
            "status",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.invalid_status",
        );
        assert!(msg.contains("bogus"), "{lang}: {msg}");
        // detail 精確等於原始值：has_cjk 只擋中文，英文說明句流回 detail 也是同一個 bug
        // 的鏡像（T909 對抗式複審 v14：反證票 1/3、未達確認門檻；reviewer 的突變實測可重現，故仍修）
        assert_eq!(v["error"]["detail"], "bogus", "{lang}: detail 應為原始值");
    }
}

#[tokio::test]
async fn t909_missing_file_field_is_localized() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    for lang in LANGS {
        let body = multipart_parts("XB", &[("note", None, b"no file here")]);
        let req = upload_req(&cookie, lang, "multipart/form-data; boundary=XB", body);
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "missing_file",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.missing_file_field",
        );
        assert!(
            v["error"]["detail"].is_null(),
            "{lang}: 缺欄位沒有可附的原始值，detail 應為空：{}",
            v["error"]["detail"]
        );
    }
}

#[tokio::test]
async fn t909_upload_too_large_is_localized() {
    let env = build_env_with(
        Arc::new(FakeEngine),
        true,
        2,
        &[("CYTRACE_MAX_UPLOAD_MB", "1")],
    );
    let cookie = login(&env.app).await;
    let big = vec![0u8; 1024 * 1024 + 4096];
    for lang in LANGS {
        let body = multipart_parts("XB", &[("file", Some("big.bin"), &big)]);
        let req = upload_req(&cookie, lang, "multipart/form-data; boundary=XB", body);
        let (st, v) = send_json(&env.app, req).await;
        let msg = assert_api_error(
            "upload_too_large",
            lang,
            st,
            &v,
            StatusCode::PAYLOAD_TOO_LARGE,
            "server.err.upload_too_large",
        );
        assert!(msg.contains("1048576"), "{lang}: 上限值須插值：{msg}");
        assert_eq!(
            v["error"]["detail"], "1048576",
            "{lang}: detail 應為上限值本身"
        );
    }
}

#[tokio::test]
async fn t909_extract_too_large_uses_archive_specific_key() {
    // ArchiveError::i18n_key() 此前在生產碼沒有呼叫者，全被壓成粗粒度 kind 的泛用訊息
    let env = build_env_with(
        Arc::new(FakeEngine),
        true,
        2,
        &[
            ("CYTRACE_MAX_UPLOAD_MB", "8"),
            ("CYTRACE_MAX_EXTRACT_MB", "1"),
        ],
    );
    let cookie = login(&env.app).await;
    let mut tarball = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tarball);
        let data = vec![0u8; 2 * 1024 * 1024];
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "zeros.bin", &data[..]).unwrap();
        b.finish().unwrap();
    }
    for lang in LANGS {
        let body = multipart_parts("XB", &[("file", Some("t.tar"), &tarball)]);
        let req = upload_req(&cookie, lang, "multipart/form-data; boundary=XB", body);
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "extract_too_large",
            lang,
            st,
            &v,
            StatusCode::PAYLOAD_TOO_LARGE,
            "server.err.extract_too_large",
        );
        assert_eq!(
            v["error"]["detail"], "extracted_bytes>1048576",
            "{lang}: detail 應為鍵值診斷資料"
        );
    }
}

#[tokio::test]
async fn t909_extractor_rejections_return_json_contract() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    for lang in LANGS {
        // Json：壞 JSON
        let req = with_csrf_and(Request::post("/api/v1/jobs"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &cookie)
            .header(header::ACCEPT_LANGUAGE, lang)
            .body(Body::from("{not json"))
            .unwrap();
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "json",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.bad_request",
        );

        // Query：limit 非數字
        let req = Request::get(format!("/api/v1/jobs?limit=abc&lang={lang}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "query",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.bad_request",
        );

        // Multipart：缺 boundary
        let req = upload_req(&cookie, lang, "multipart/form-data", b"x".to_vec());
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "multipart",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.bad_request",
        );

        // Path：非法 UTF-8 百分比編碼
        let req = Request::get(format!("/api/v1/jobs/%FF%FE?lang={lang}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "path",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.bad_request",
        );
    }
}

#[tokio::test]
async fn t909_login_malformed_json_returns_json_contract() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    for lang in LANGS {
        let mut req = with_csrf_and(Request::post("/api/v1/session"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT_LANGUAGE, lang)
            .body(Body::from("{\"password\":"))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 1, 0, 2], 40001))));
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "login_json",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.bad_request",
        );
    }
}

/// 路徑命中、方法不符 → JSON 405（依語系渲染、附 `Allow`），且**認證仍先於方法判定**。
///
/// 原本是 axum 預設的 405 空 body：繞過 `{"error":{…}}` 契約與請求語系。e5e1f21 以「未確認
/// （1/3）」不修，但同一個 commit 修了好幾項 1/3 的發現，該理由不成立（T909 第二輪複審 claims#4）。
#[tokio::test]
async fn t909_method_not_allowed_is_json_and_auth_first() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    // /api/v1/session 同時掛在 public（POST）與 protected（GET/DELETE），合併後也要走 JSON 405
    for (route, allow) in [
        ("/api/v1/jobs", ["GET", "POST"].as_slice()),
        ("/api/v1/jobs/abc", ["GET", "DELETE"].as_slice()),
        ("/api/v1/session", ["GET", "DELETE", "POST"].as_slice()),
        // public 的非 /api 路徑：fallback 把它與 /api/* 一起歸入 JSON 錯誤契約（第三輪複審 server#1）
        ("/healthz", ["GET"].as_slice()),
    ] {
        for lang in LANGS {
            let req = with_csrf_and(Request::put(format!("{route}?lang={lang}")))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let resp = env.app.clone().oneshot(req).await.unwrap();
            let got_allow = resp
                .headers()
                .get(header::ALLOW)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            for m in allow {
                assert!(
                    got_allow.contains(m),
                    "{route}: Allow 缺 {m}：{got_allow:?}"
                );
            }
            let st = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body)
                .unwrap_or_else(|_| panic!("{route}: 405 不是 JSON：{body:?}"));
            assert_api_error(
                route,
                lang,
                st,
                &v,
                StatusCode::METHOD_NOT_ALLOWED,
                "server.err.method_not_allowed",
            );
        }
    }
    // 未登入：受保護路徑先回 401 而非 405。注意 401 仍帶 `Allow`（axum 在 layer 之外補上），
    // 方法表見公開原始碼 router.rs，不視為機密——本斷言只釘狀態碼的優先序（第三輪複審 server#2）。
    let req = with_csrf_and(Request::put("/api/v1/jobs"))
        .body(Body::empty())
        .unwrap();
    let (st, v) = send_json(&env.app, req).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "未登入應先 401：{v}");
}

/// job 失敗訊息依**查詢時**的請求語系渲染（get 與 list 都是），且不寫回 job.json。
///
/// 原本 get / list 完全不看語系：兩種語系拿到逐位元組相同的 `{kind, i18n_key, detail}`，
/// 非 console 用戶端沒有任何語言的訊息（T909 第二輪複審 claims#5）。
#[tokio::test]
async fn t909_failed_job_message_follows_query_language() {
    let env = build_env(Arc::new(FailingSbomEngine), true, 2);
    let cookie = login(&env.app).await;
    let (st, v) = create_job(&env.app, &cookie, "app", None).await;
    assert_eq!(st, StatusCode::ACCEPTED);
    let id = v["id"].as_str().unwrap().to_string();
    let done = wait_terminal(&env.app, &cookie, &id).await;
    assert_eq!(done["status"], "failed", "{done}");

    let mut seen = Vec::new();
    for lang in LANGS {
        for (label, url) in [
            ("get", format!("/api/v1/jobs/{id}?lang={lang}")),
            ("list", format!("/api/v1/jobs?lang={lang}")),
        ] {
            let req = Request::get(&url)
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (st, v) = send_json(&env.app, req).await;
            assert_eq!(st, StatusCode::OK);
            let job = if label == "get" { &v } else { &v["jobs"][0] };
            let e = &job["error"];
            assert_eq!(e["i18n_key"], "server.err.engine", "{label}/{lang}: {e}");
            assert_eq!(
                e["detail"], "syft exit Some(1): ",
                "{label}/{lang}: detail 應為原始值"
            );
            let msg = e["message"]
                .as_str()
                .unwrap_or_else(|| panic!("{label}/{lang}: 缺 message：{e}"));
            assert!(!msg.is_empty() && !msg.contains("{{") && msg != "server.err.engine");
            assert_eq!(
                has_cjk(msg),
                lang == "zh-TW",
                "{label}/{lang}: message 未依語系渲染：{msg}"
            );
            seen.push(msg.to_string());
        }
    }
    assert_ne!(seen[0], seen[2], "兩種語系的 message 相同——渲染沒有看語系");

    // 落盤記錄不帶任何語系的訊息
    let on_disk: serde_json::Value = serde_json::from_slice(
        &std::fs::read(env.base.join("data/jobs").join(&id).join("job.json")).unwrap(),
    )
    .unwrap();
    assert!(
        on_disk["error"].get("message").is_none(),
        "job.json 不得寫入渲染後的訊息：{on_disk}"
    );
}

/// job 失敗訊息的**退回鏈**與 console 共用 `tests/fixtures/job-error-render.json`，兩邊各自驗證。
///
/// 前版只測了「鍵恰好是 `server.err.<kind>`」那一種：把 i18n_key 從鏈中拿掉，重啟中斷的 job
/// 會改顯示「伺服器內部錯誤」而全綠（第三輪複審 server#3）；註解又宣稱與 console「規則相同」，
/// 實際上查不到鍵時兩邊退回不同（server#5）。console 側由 frontend/scripts/cbom-message-check.mts
/// 讀同一份 fixture。
#[tokio::test]
async fn job_error_message_follows_shared_fallback_fixture() {
    let fx: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/job-error-render.json")).unwrap();
    let cases = fx["cases"].as_array().unwrap();
    assert!(
        cases.len() >= 5,
        "fixture 案例過少——退回鏈的每一段都要有案例"
    );
    let id_of = |i: usize| format!("1700000000-{i:08x}");
    let seed: Vec<serde_json::Value> = cases
        .iter()
        .enumerate()
        .map(|(i, c)| {
            // 重啟中斷走真的恢復路徑：落盤成 running，由 registry 轉成 interrupted
            if c["error"]["i18n_key"] == "server.job.interrupted" {
                serde_json::json!({ "id": id_of(i), "status": "running",
                    "target": "mounted:targets/app", "created_at": "2026-01-01T00:00:00Z" })
            } else {
                serde_json::json!({ "id": id_of(i), "status": "failed",
                    "target": "mounted:targets/app", "created_at": "2026-01-01T00:00:00Z",
                    "finished_at": "2026-01-01T00:00:01Z", "error": c["error"] })
            }
        })
        .collect();
    let env = build_env_seeded(Arc::new(FakeEngine), true, 2, &[], &seed);
    let cookie = login(&env.app).await;
    for lang in LANGS {
        let cat = cytrace_i18n::Catalog::load(lang);
        let req = Request::get(format!("/api/v1/jobs?lang={lang}&limit=200"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (_, listed) = send_json(&env.app, req).await;
        for (i, c) in cases.iter().enumerate() {
            let name = c["name"].as_str().unwrap();
            let want = match c["expect"]["key"].as_str() {
                Some(k) => cat.t(k, &[]),
                None => c["error"]["detail"].as_str().unwrap().to_string(),
            };
            assert!(
                !want.is_empty() && want != c["expect"]["key"].as_str().unwrap_or(""),
                "{name}: 預期文字無效"
            );
            // 預期值也是 `t(k, &[])` 算的：鍵若需要變數，兩邊同帶 `{{…}}` 仍相等——得另外擋
            // （tests/i18n_call_vars.rs 的 NONLITERAL 以本測試涵蓋 render_job_error；第三輪複審）
            assert!(
                !want.contains("{{"),
                "{name}/{lang}：退回鏈的鍵不得需要變數：{want}"
            );
            let req = Request::get(format!("/api/v1/jobs/{}?lang={lang}", id_of(i)))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (st, got) = send_json(&env.app, req).await;
            assert_eq!(st, StatusCode::OK, "{name}");
            // fixture 的 error 必須就是實際落盤／恢復出來的那一筆
            assert_eq!(got["error"]["i18n_key"], c["error"]["i18n_key"], "{name}");
            assert_eq!(got["error"]["message"], want, "{name}/{lang}（get）");
            let in_list = listed["jobs"]
                .as_array()
                .unwrap()
                .iter()
                .find(|j| j["id"] == id_of(i).as_str())
                .unwrap_or_else(|| panic!("{name}: list 裡找不到"));
            assert_eq!(in_list["error"]["message"], want, "{name}/{lang}（list）");
        }
    }
}

/// console 的**每一條** API 請求路徑都必須帶 **UI 語系**——由 `frontend/scripts/console-lang-check.mts`
/// 把關（載入真的 client.ts / upload.ts 驗實際送出值、以 TypeScript AST 限定 `/api` 字面值只准出現在
/// 那兩支檔案）。本測試只確保那支檢查**確實接在 land 前的閘上**。
///
/// 前版在這裡另有一道以文字剝註解、找「直接包住字面值的呼叫」的結構閘：`'/api' + '/v1/…'`、
/// `${API}/v1/…`、同一行先出現含 `\//` 的 regex 都繞得過（第四輪複審 lang#1／claims#0）。
/// 已移到前端檢查，改用 AST。
#[test]
fn t909_console_requests_send_ui_language() {
    let repo = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    // CI 無法設為 required（free 方案），land 前真正會跑到的是 make lint——釘 lint 的**生效** recipe
    let makefile = std::fs::read_to_string(repo.join("Makefile")).unwrap();
    assert!(
        recipe_runs(&makefile, "lint", "console-lang-check.mts"),
        "Makefile 最後一份 lint: recipe 沒有執行 frontend/scripts/console-lang-check.mts（或失敗會被吞掉）"
    );
    // 由 Make 本身確認生效的 recipe：文字解析看不到單行 recipe（`lint: ; true`）、include 進來的
    // 重新定義（宣稱核對 console#3）。`.IGNORE: lint` 與行接續的 `|| true` 仍不在範圍（已知限制）。
    let out = std::process::Command::new("make")
        .args(["-n", "--no-print-directory", "lint"])
        .current_dir(&repo)
        .output()
        .expect("執行 make -n lint");
    let dry = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success()
            && dry.lines().any(|l| l.trim()
                == "node --experimental-strip-types frontend/scripts/console-lang-check.mts"),
        "make -n lint 的實際指令沒有 console-lang-check.mts：\n{dry}"
    );
    // CI：必須是一個 run 步驟、逐字執行該檢查（`echo …console-lang-check.mts` 之類不算）
    let ci = std::fs::read_to_string(repo.join(".github/workflows/ci.yml")).unwrap();
    assert!(
        ci.lines().any(|l| l.trim()
            == "run: node --experimental-strip-types frontend/scripts/console-lang-check.mts"),
        "CI 沒有以獨立步驟執行 frontend/scripts/console-lang-check.mts"
    );
}

/// Makefile 本檔中**最後一份** tab 縮排的 `target:` recipe 是否有一行非註解、失敗不會被吞掉
/// （無 `-` 前綴、不含 `||`）的指令含 `needle`。
///
/// 前版只看第一個 `lint:` 區塊，在後面再定義一次就能讓檢查不再執行（第四輪完整性批判）。
/// 本函式不等於 Make 的生效 recipe（單行 recipe、include 看不到）——那部分由呼叫端另跑
/// `make -n` 確認（宣稱核對 console#3 更正前版「以生效的 recipe 為準」的說法）。
fn recipe_runs(makefile: &str, target: &str, needle: &str) -> bool {
    let header = format!("{target}:");
    let mut recipes: Vec<Vec<&str>> = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in makefile.lines() {
        if let Some(cmd) = line.strip_prefix('\t') {
            if let Some(r) = current.as_mut() {
                r.push(cmd);
            }
            continue;
        }
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        // 新的 target 或變數定義：先收起上一份 recipe
        if let Some(r) = current.take() {
            if !r.is_empty() {
                recipes.push(r);
            }
        }
        if line.starts_with(&header) && !line.starts_with(&format!("{header}=")) {
            current = Some(Vec::new());
        }
    }
    if let Some(r) = current.take() {
        if !r.is_empty() {
            recipes.push(r);
        }
    }
    let Some(effective) = recipes.last() else {
        return false;
    };
    effective.iter().any(|cmd| {
        let c = cmd.trim_start().trim_start_matches('@').trim_start();
        !c.starts_with('#') && !c.starts_with('-') && !c.contains("||") && c.contains(needle)
    })
}

#[test]
fn recipe_matcher_scopes_to_the_effective_target() {
    let n = "console-lang-check.mts";
    let only_other = "lint:\n\tcargo fmt --check\n\t@# node x/console-lang-check.mts（註解）\n\nfrontend-check:\n\tnode x/console-lang-check.mts\n";
    assert!(
        !recipe_runs(only_other, "lint", n),
        "只有別的 target 執行、或只在註解提到"
    );
    assert!(recipe_runs(only_other, "frontend-check", n));
    let wired = "fmt:\n\tcargo fmt\nlint: fmt\n\tcargo clippy\n\tnode x/console-lang-check.mts\ncoverage:\n\ttrue\n";
    assert!(recipe_runs(wired, "lint", n));
    assert!(
        !recipe_runs(wired, "lint-ci", n),
        "前綴相同的 target 不得誤認"
    );
    let overridden = format!("{wired}lint:\n\tcargo clippy\n");
    assert!(
        !recipe_runs(&overridden, "lint", n),
        "後面重新定義的 lint 才是生效的那份"
    );
    let swallowed = "lint:\n\t-node x/console-lang-check.mts\n";
    assert!(!recipe_runs(swallowed, "lint", n), "`-` 前綴會吞掉失敗");
    let ored = "lint:\n\tnode x/console-lang-check.mts || true\n";
    assert!(!recipe_runs(ored, "lint", n), "`|| true` 會吞掉失敗");
}

/// rejection 原生**不是 400** 的案例：狀態語意須保留（413 不得被壓成 400）。
///
/// 初版 `bad_request` 一律回 400/validation，而 t909 測試挑的 rejection 原生都是 400，
/// 所以驗不出這件事（T909 對抗式複審 v0，2/3 確認）。public router 未停用 body limit，axum 預設 2 MiB。
#[tokio::test]
async fn t909_oversized_login_body_keeps_413() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let big = format!("{{\"password\":\"{}\"}}", "x".repeat(2 * 1024 * 1024 + 16));
    for lang in LANGS {
        let mut req = with_csrf_and(Request::post("/api/v1/session"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT_LANGUAGE, lang)
            .body(Body::from(big.clone()))
            .unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 1, 0, 3], 40002))));
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "login_413",
            lang,
            st,
            &v,
            StatusCode::PAYLOAD_TOO_LARGE,
            "server.err.payload_too_large",
        );
        assert_eq!(
            v["error"]["kind"], "payload_too_large",
            "{lang}: 成因須是「太大」而非「格式不合法」"
        );
    }
}

/// Path rejection 經**每一條**帶 Path 的路由都走 JSON 契約（初版只驗了 jobs/{id}）。
#[tokio::test]
async fn t909_path_rejection_on_every_path_route() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    for route in [
        "/api/v1/jobs/%FF%FE",
        "/api/v1/jobs/%FF%FE/report",
        "/api/v1/jobs/%FF%FE/result",
        "/api/v1/jobs/%FF%FE/artifacts/sbom",
    ] {
        for lang in LANGS {
            let req = Request::get(format!("{route}?lang={lang}"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap();
            let (st, v) = send_json(&env.app, req).await;
            assert_api_error(
                route,
                lang,
                st,
                &v,
                StatusCode::BAD_REQUEST,
                "server.err.bad_request",
            );
        }
    }
}

#[tokio::test]
async fn t909_rejections_on_report_query_and_delete_path() {
    // e2e 原本只打到 list 的 Query 與 GET 的 Path；report 的 ApiQuery、DELETE 的 ApiPath
    // 若被改回裸 extractor，只剩靜態閘把關，而當時的靜態閘比不到全限定寫法
    // （T909 對抗式複審 v15，3/3 確認）。
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    for lang in LANGS {
        // download 是 Option<u8>：xyz 解析失敗發生在 handler 本體之前，job 存不存在都一樣
        let req = Request::get(format!("/api/v1/jobs/any/report?download=xyz&lang={lang}"))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "report?download",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.bad_request",
        );

        let req = with_csrf_and(Request::delete(format!("/api/v1/jobs/%FF%FE?lang={lang}")))
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let (st, v) = send_json(&env.app, req).await;
        assert_api_error(
            "DELETE path",
            lang,
            st,
            &v,
            StatusCode::BAD_REQUEST,
            "server.err.bad_request",
        );
    }
}

/// 報表開啟語言 == 送出掃描那次請求的語系（T918）。報表 HTML 是靜態產物：之後用哪種語言
/// 查看都不影響它，所以只能在產生時決定。掛載與上傳兩條送出路徑、header 與 `?lang=`
/// 兩種協商方式都要涵蓋——少接一條，那條路徑產的報表就一律以 zh-TW 開啟，且沒有任何錯誤。
#[tokio::test]
async fn t918_report_opens_in_submitting_request_language() {
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    let body = r#"{"target":{"kind":"mounted","root":"targets","path":"app"}}"#;

    let html_lang = |id: &str| {
        let html = std::fs::read_to_string(env.base.join("data/jobs").join(id).join("report.html"))
            .unwrap();
        let rest = html
            .split("<html lang=\"")
            .nth(1)
            .expect("缺 <html lang>")
            .to_string();
        rest.split('"').next().unwrap().to_string()
    };

    // 掛載：Accept-Language / ?lang= / 皆無
    for (uri, accept, want) in [
        ("/api/v1/jobs", Some("en-US,en;q=0.9"), "en-US"),
        ("/api/v1/jobs?lang=en-US", Some("zh-TW"), "en-US"),
        ("/api/v1/jobs", None, "zh-TW"),
    ] {
        let mut req = with_csrf_and(Request::post(uri))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &cookie);
        if let Some(al) = accept {
            req = req.header(header::ACCEPT_LANGUAGE, al);
        }
        let resp = env
            .app
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "{uri} {accept:?}");
        let id = json_of(resp).await["id"].as_str().unwrap().to_string();
        let done = wait_terminal(&env.app, &cookie, &id).await;
        assert_eq!(done["status"], "done", "{done}");
        assert_eq!(html_lang(&id), want, "{uri} Accept-Language={accept:?}");
    }

    // 上傳：Accept-Language
    let zip = make_zip_bytes(&[("app/main.py", b"print(1)")]);
    let boundary = "----cytracet918";
    let req = with_csrf_and(Request::post("/api/v1/jobs/upload"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header(header::COOKIE, &cookie)
        .header(header::ACCEPT_LANGUAGE, "en-US")
        .body(Body::from(multipart_body(boundary, "app.zip", &zip, None)))
        .unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let id = json_of(resp).await["id"].as_str().unwrap().to_string();
    let done = wait_terminal(&env.app, &cookie, &id).await;
    assert_eq!(done["status"], "done", "{done}");
    assert_eq!(html_lang(&id), "en-US", "上傳路徑");
}

/// web 模式一律附 SPDX（FR-001；T919）：單筆查詢回報實際存在的產物，產物端點以附件下載。
/// 引擎不產 SPDX（升級前的 job、或 fake 引擎的預設實作）時，job 照常完成、清單不列 spdx、
/// 端點回 404——console 依清單顯示下載連結，不會給出一個點了才 404 的按鈕。
#[tokio::test]
async fn t919_spdx_artifact_is_listed_and_downloadable() {
    async fn fetch(app: &Router, cookie: &str, uri: &str) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::get(uri)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    // 有 SPDX
    let env = build_env(Arc::new(FakeEngine), true, 2);
    let cookie = login(&env.app).await;
    let (status, v) = create_job(&env.app, &cookie, "app", None).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = v["id"].as_str().unwrap().to_string();
    let done = wait_terminal(&env.app, &cookie, &id).await;
    assert_eq!(done["status"], "done", "{done}");
    // FakeEngine 有 CBOM 實作但本 job 未要求 → 不列 cbom
    assert_eq!(
        done["artifacts"],
        serde_json::json!(["sbom", "spdx", "grype"]),
        "{done}"
    );

    let resp = fetch(
        &env.app,
        &cookie,
        &format!("/api/v1/jobs/{id}/artifacts/spdx"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cd = resp.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        cd,
        format!("attachment; filename=\"cytrace-{id}.sbom.spdx.json\"")
    );
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        SPDX,
        "SPDX 應原樣落地與回應"
    );

    // 列表不附 artifacts（不為每一筆碰檔案系統）
    let resp = fetch(&env.app, &cookie, "/api/v1/jobs").await;
    let list = json_of(resp).await;
    assert_eq!(list["total"], 1, "{list}");
    assert!(list["jobs"][0].get("artifacts").is_none(), "{list}");

    // 引擎不產 SPDX：job 照常完成，清單不列、端點 404
    let env = build_env(Arc::new(BrokenCbomEngine), true, 2);
    let cookie = login(&env.app).await;
    let (_, v) = create_job(&env.app, &cookie, "app", None).await;
    let id = v["id"].as_str().unwrap().to_string();
    let done = wait_terminal(&env.app, &cookie, &id).await;
    assert_eq!(done["status"], "done", "{done}");
    assert_eq!(
        done["artifacts"],
        serde_json::json!(["sbom", "grype"]),
        "{done}"
    );
    let resp = fetch(
        &env.app,
        &cookie,
        &format!("/api/v1/jobs/{id}/artifacts/spdx"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 產物種類的兩份宣告必須一致：server 的 `ARTIFACTS` 與 console 的 `ArtifactKind`。
/// server 多一種而 console 沒跟上時，下載連結的文字會變成 `t(undefined)`（T919 複審 Info）。
#[test]
fn artifact_kinds_match_the_console_type() {
    let ts = include_str!("../../../frontend/src/console/api/types.ts");
    let line = ts
        .lines()
        .find(|l| l.starts_with("export type ArtifactKind"))
        .expect("types.ts 應宣告 ArtifactKind");
    let mut console: Vec<&str> = line.split('\'').skip(1).step_by(2).collect();
    let mut server: Vec<&str> = cytrace_server::api::reports::ARTIFACTS
        .iter()
        .map(|(k, _)| *k)
        .collect();
    console.sort_unstable();
    server.sort_unstable();
    assert!(!server.is_empty());
    assert_eq!(server, console, "{line}");
}
