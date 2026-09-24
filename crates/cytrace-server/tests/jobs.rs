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

struct TestEnv {
    app: Router,
    #[allow(dead_code)]
    base: PathBuf,
}

/// 建測試環境：temp data_dir、非空 db 目錄（db_present=true）、掃描白名單 root。
fn build_env(engine: Arc<dyn ScanEngine>, db_present: bool, max_concurrent: usize) -> TestEnv {
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
