// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "bee-rust")]
use std::sync::Arc;
use std::time::Duration;

use bee_cache::MemoryCache;
use bee_router::context::RouterError; // bee_router 未在根 re-export RouterError（仅 context 模块公开）
use bee_router::{Context, Controller};
use bee_session::Session;
use bee_template::TemplateEngine;
use serde_json::json;

use jwt_rust::config::{JwtConfig, MiddlewareConfig};
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::bee_rust::JwtFilter;
use jwt_rust::jwt::JwtPayload;

const TTL: Duration = Duration::from_secs(3600);

fn templates() -> Arc<TemplateEngine> {
    let dir = std::env::temp_dir().join(format!("jwt_rust_bee_tpl_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("noop.html"), "ok").unwrap();
    Arc::new(TemplateEngine::new(&dir).unwrap())
}

/// `path` 的 Context，可带原始 Authorization 头值
fn context(path: &str, auth_header: Option<&str>) -> Context {
    let cache: Arc<dyn bee_cache::Cache> = Arc::new(MemoryCache::new());
    let session = Session::new(cache, TTL);
    let mut req = axum::http::Request::builder().uri(path);
    if let Some(h) = auth_header {
        req = req.header("Authorization", h);
    }
    Context::new(
        req.body(axum::body::Body::empty()).unwrap(),
        session,
        templates(),
    )
}

fn cache() -> Arc<dyn bee_cache::Cache> {
    Arc::new(MemoryCache::new())
}

struct Noop;

#[async_trait::async_trait]
impl Controller for Noop {
    async fn handle(&self, _ctx: &mut Context) -> Result<(), RouterError> {
        Ok(())
    }
}

fn auth(except: Vec<String>) -> Arc<JwtAuth> {
    Arc::new(
        JwtAuth::from_config(JwtConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            middleware: MiddlewareConfig { except },
            ..Default::default()
        })
        .unwrap(),
    )
}

#[tokio::test]
async fn filter_blocks_passes_and_attaches_payload() {
    let a = auth(vec![]);
    let f = JwtFilter::new(a.clone());

    // 无 token → abort 401 + 统一 JSON 体
    let mut ctx = context("/api/me", None);
    ctx.dispatch(cache(), TTL, &[&f], &Noop).await.unwrap();
    assert!(ctx.is_aborted());
    let resp = ctx.into_response();
    assert_eq!(resp.status(), 401);
    // 401 响应头契约（钉住 content-type，与其余适配层一致、不带 charset）
    assert_eq!(resp.headers()["content-type"], "application/json");
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["code"], 401);
    assert_eq!(v["msg"], "Token not provided");
    assert!(v["data"].is_null());

    // 有效 token → 未 abort，payload 经 request extensions 挂出
    let token = a.jwt().encode(&json!({"user_id": 7}), None).unwrap();
    let mut ctx = context("/api/me", Some(&format!("Bearer {token}")));
    ctx.dispatch(cache(), TTL, &[&f], &Noop).await.unwrap();
    assert!(!ctx.is_aborted());
    let payload = ctx.request.extensions().get::<JwtPayload>().unwrap();
    assert_eq!(payload.get("user_id").unwrap(), 7);
}

#[tokio::test]
async fn except_path_skips_and_expired_token_is_401() {
    let a = auth(vec!["/api/login".into()]);
    let f = JwtFilter::new(a.clone());

    // except 路径：无 token 也不 abort
    let mut ctx = context("/api/login", None);
    ctx.dispatch(cache(), TTL, &[&f], &Noop).await.unwrap();
    assert!(!ctx.is_aborted());

    // 过期令牌 → abort 401（直签：Jwt::encode 的 exp 恒被覆写，签不出过期令牌）
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({"iss": "", "aud": "", "exp": n - 30, "nbf": n - 60, "iat": n - 60, "jti": "bee-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let mut ctx = context("/api/me", Some(&format!("Bearer {expired}")));
    ctx.dispatch(cache(), TTL, &[&f], &Noop).await.unwrap();
    assert!(ctx.is_aborted());
    let resp = ctx.into_response();
    assert_eq!(resp.status(), 401);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["msg"], "Token has expired");
}
