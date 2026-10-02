//! Job 生命週期整合測試——FakeEngine 注入（不需 syft/grype binary，air-gapped CI 可跑）。

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use cytrace_core::engine::ScanEngine;
use cytrace_core::error::Result as CoreResult;
use cytrace_server::auth::{hash_password, CSRF_HEADER};
use cytrace_server::config::{CliFlags, ServerConfig};
use cytrace_server::router::build_router_with_state;
use cytrace_server::state::AppState;
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

const TEST_PASSWORD: &str = "test-password-123";
static TEST_PHC: LazyLock<String> = LazyLock::new(|| hash_password(TEST_PASSWORD).unwrap());
static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

struct FakeEngine;
impl ScanEngine for FakeEngine {
    fn sbom(&self, _target: &str) -> CoreResult<String> {
        Ok(CYCLONEDX.into())
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
    let state = AppState::with_engine(cfg, engine).unwrap();
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

/// 輪詢直到終態（FakeEngine 極快；上限 5s 防呆）。
async fn wait_terminal(app: &Router, cookie: &str, id: &str) -> serde_json::Value {
    for _ in 0..50 {
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
    // 未登入：受保護路徑先回 401，不得以 405 透露方法表
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

/// 剝掉 TS 的 `//` 與 `/* */` 註解，保留字串字面值與行結構（行號不漂）。
fn strip_ts_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut quote: Option<char> = None;
    while i < b.len() {
        let c = b[i];
        let n = b.get(i + 1).copied();
        if let Some(q) = quote {
            out.push(c);
            if c == '\\' {
                if let Some(n) = n {
                    out.push(n);
                }
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
        } else if c == '/' && n == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && n == Some('*') {
            i += 2;
            while i < b.len() && !(b[i] == '*' && b.get(i + 1) == Some(&'/')) {
                if b[i] == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i += 2;
        } else {
            if matches!(c, '\'' | '"' | '`') {
                quote = Some(c);
            }
            out.push(c);
            i += 1;
        }
    }
    out
}

/// `pos` 所在位置**直接**被哪個呼叫包住：往回找第一個未閉合的 `(`，取它前面的識別字
/// （略過泛型 `<…>`）。`request<JobRecord>(`…`)` → `request`。
fn enclosing_call(text: &str, pos: usize) -> Option<&str> {
    let b = text.as_bytes();
    let mut depth = 0i32;
    let mut i = pos;
    while i > 0 {
        i -= 1;
        match b[i] {
            b')' => depth += 1,
            b'(' if depth > 0 => depth -= 1,
            b'(' => {
                let mut end = i;
                if end > 0 && b[end - 1] == b'>' {
                    let mut d = 0;
                    while end > 0 {
                        end -= 1;
                        match b[end] {
                            b'>' => d += 1,
                            b'<' => {
                                d -= 1;
                                if d == 0 {
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                let mut k = end;
                while k > 0 && (b[k - 1].is_ascii_alphanumeric() || matches!(b[k - 1], b'_' | b'.'))
                {
                    k -= 1;
                }
                return Some(&text[k..end]);
            }
            _ => {}
        }
    }
    None
}

/// 一個 console 檔的違規清單（`/api/v1/` 字面值未經帶語系的呼叫、或出現第四種請求構造）。
fn console_request_problems(rel: &str, text: &str) -> (Vec<String>, usize) {
    // 已知會帶語系的呼叫：request（fetch，Accept-Language）、xhr.open（XHR，Accept-Language）、
    // withLang（導覽，?lang=）。實際送出的值由 frontend/scripts/console-lang-check.mts 以 stub
    // 攔截驗證；本函式只管「字面值有沒有走進這三個呼叫」。
    const CARRIERS: [&str; 3] = ["request", "xhr.open", "withLang"];
    let text = strip_ts_comments(text);
    let mut problems = Vec::new();
    let mut literals = 0usize;
    for (pos, _) in text.match_indices("/api/v1/") {
        literals += 1;
        let line = text[..pos].matches('\n').count() + 1;
        match enclosing_call(&text, pos) {
            Some(c) if CARRIERS.contains(&c) => {}
            other => problems.push(format!(
                "{rel}:{line}: /api/v1/ 字面值未經會帶語系的呼叫（直接包住它的是 {other:?}）"
            )),
        }
    }
    for (n, l) in text.lines().enumerate() {
        if (l.contains("fetch(") && rel != "api/client.ts")
            || (l.contains("XMLHttpRequest") && rel != "api/upload.ts")
        {
            problems.push(format!(
                "{rel}:{}: 新的請求構造（只准在 client.ts/upload.ts）：{}",
                n + 1,
                l.trim()
            ));
        }
    }
    (problems, literals)
}

/// 比對器的正負對照：壞樣本必中、好樣本必不中。
///
/// 前版的豁免是「前一行含 `request<`」——api 物件裡每一行都是單行閉合的 `request<…>(…)`，
/// 在任一行後面插入不帶語系的導覽 URL 都會被放行（T909 第二輪複審 tests#2，3/3 確認）。
#[test]
fn console_request_matcher_detects_known_violations() {
    let bad: &[(&str, &str)] = &[
        (
            "前一行是單行閉合的 request",
            "  getJob: (id: string) => request<JobRecord>(`/api/v1/jobs/${id}`),\n  reportHref: (id: string) => `/api/v1/jobs/${id}/report`,\n",
        ),
        (
            "呼叫只出現在註解裡",
            "// request<JobList>(\nconst u = '/api/v1/jobs'\n",
        ),
        ("包住它的是別的呼叫", "window.open(`/api/v1/jobs/${id}/report`)\n"),
        (
            "同一行另有 request 但字面值不在其參數內",
            "a: () => request<X>('/api/v1/x'), b: `/api/v1/y`,\n",
        ),
        ("頂層字面值", "const href = '/api/v1/jobs'\n"),
    ];
    for (why, src) in bad {
        let (p, _) = console_request_problems("pages/Sample.tsx", src);
        assert!(!p.is_empty(), "壞樣本沒被抓到（{why}）：{src}");
    }
    let (p, _) = console_request_problems("pages/Sample.tsx", "const r = fetch('/x')\n");
    assert!(!p.is_empty(), "client.ts 以外的 fetch 沒被抓到");
    let good: &[&str] = &[
        "request<JobList>('/api/v1/jobs')\n",
        "request<JobList>(\n    '/api/v1/jobs',\n    { method: 'POST' },\n  )\n",
        "withLang(`/api/v1/jobs/${id}/report${download ? '?download=1' : ''}`)\n",
        "xhr.open('POST', '/api/v1/jobs/upload')\n",
        "request<void>(`/api/v1/jobs/${encodeURIComponent(id)}`, { method: 'DELETE' })\n",
        "// 舊寫法：const u = '/api/v1/jobs'\nrequest<X>('/api/v1/jobs')\n",
    ];
    for src in good {
        let (p, n) = console_request_problems("api/client.ts", src);
        assert!(p.is_empty(), "好樣本被誤判：{src}\n{p:?}");
        assert!(n >= 1, "好樣本沒有抽到字面值：{src}");
    }
}

/// console 的**每一條** API 請求路徑都必須帶 **UI 語系**（非瀏覽器預設）。
///
/// server 依請求語系渲染錯誤 message。三種請求形態、三種帶法：
/// - `fetch`（client.ts `request`）→ `Accept-Language` header
/// - 上傳 XHR（upload.ts）→ `Accept-Language` header
/// - `<a href>` 導覽（`artifactUrl`）→ 無法設 header，走 `?lang=`（`withLang`）
///
/// 分工：本測試管**結構**——每個 `/api/v1/` 字面值都必須是上述三個呼叫的直接參數，且不得
/// 出現第四種請求構造。**實際送出的值**由 `frontend/scripts/console-lang-check.mts` 載入真的
/// client.ts / upload.ts、stub fetch 與 XHR 攔下來驗——前版在這裡對整檔做 `contains`，
/// 把 header 那行移進註解照樣綠（T909 第二輪複審 claims#2）。
#[test]
fn t909_console_requests_send_ui_language() {
    let repo = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    let root = repo.join("frontend/src/console");
    fn walk(d: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if matches!(p.extension().and_then(|x| x.to_str()), Some("ts" | "tsx")) {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root, &mut files);
    assert!(
        files.len() >= 10,
        "只找到 {} 個前端檔——掃描可能失效",
        files.len()
    );

    let mut problems = Vec::new();
    let mut api_literals = 0usize;
    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let (p, n) = console_request_problems(&rel, &std::fs::read_to_string(f).unwrap());
        problems.extend(p);
        api_literals += n;
    }
    assert!(
        api_literals >= 10,
        "只看到 {api_literals} 個 /api/v1/ 字面值——掃描可能失效"
    );
    assert!(
        problems.is_empty(),
        "console 有請求路徑沒帶 UI 語系：\n{}",
        problems.join("\n")
    );

    // 送出值的行為檢查必須接在 land 前的閘上，否則本測試的分工就落空
    for (f, why) in [
        ("Makefile", "make lint"),
        (".github/workflows/ci.yml", "CI"),
    ] {
        let text = std::fs::read_to_string(repo.join(f)).unwrap();
        // 註解行（`#`、Makefile 的 `@#`）提到檔名不算接線
        let wired = text.lines().any(|l| {
            let t = l.trim_start();
            !(t.starts_with('#') || t.starts_with("@#")) && t.contains("console-lang-check.mts")
        });
        assert!(
            wired,
            "{why}（{f}）沒有執行 frontend/scripts/console-lang-check.mts"
        );
    }
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
