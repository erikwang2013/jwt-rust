// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "poem")]
// 直连 `Endpoint::call(Request)` 驱动（poem 3 原生 async trait，Endpoint 的 future 可直接在 tokio 上跑）。
// 未用 `poem::test::TestClient`：它需 poem 非默认的 `test` feature；而 TestClient::send 也不过是
// `Request::builder()…finish()` + `Endpoint::get_response`（poem 3.1 `src/test/request_builder.rs`），直连等价，省去 dev-dependencies 里再声明 poem 开该 feature。
use std::sync::Arc;

use poem::middleware::Middleware;
use poem::{Endpoint, EndpointExt, Request, Route};
use serde_json::json;

use jwt_rust::config::JwtConfig;
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::poem::JwtMiddleware;
use jwt_rust::jwt::JwtPayload;

fn auth(except: Vec<String>) -> JwtAuth {
    JwtAuth::from_config(JwtConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        middleware: jwt_rust::config::MiddlewareConfig { except },
        ..Default::default()
    })
    .unwrap()
}

struct Echo;

impl Endpoint for Echo {
    type Output = String;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        match req.extensions().get::<JwtPayload>() {
            Some(p) => Ok(format!("user={}", p.get("user_id").unwrap())),
            None => Ok("user=none".into()),
        }
    }
}

#[tokio::test]
async fn middleware_flow() {
    let a = Arc::new(auth(vec!["/api/login".into()]));
    let ep = JwtMiddleware::new(a.clone()).transform(Echo);

    // 无 token → 401 JSON（三字段）
    let req = Request::builder().uri_str("/api/me").finish();
    let resp = ep.call(req).await.unwrap();
    assert_eq!(resp.status(), poem::http::StatusCode::UNAUTHORIZED);
    let body = resp.into_body().into_string().await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["code"], 401);
    assert_eq!(v["msg"], "Token not provided");
    assert!(v["data"].is_null());

    // 有效 token → payload 到 handler
    let token = a.jwt().encode(&json!({"user_id": 7}), None).unwrap();
    let req = Request::builder()
        .uri_str("/api/me")
        .header("Authorization", format!("Bearer {token}"))
        .finish();
    let resp = ep.call(req).await.unwrap();
    assert_eq!(resp.status(), poem::http::StatusCode::OK);
    let body = resp.into_body().into_string().await.unwrap();
    assert_eq!(body, "user=7");

    // except 路径无 token 放行（handler 未见 payload）
    let req = Request::builder().uri_str("/api/login").finish();
    let resp = ep.call(req).await.unwrap();
    assert_eq!(resp.status(), poem::http::StatusCode::OK);
    let body = resp.into_body().into_string().await.unwrap();
    assert_eq!(body, "user=none");
}

#[tokio::test]
async fn route_with_middleware_documented_usage() {
    let a = Arc::new(auth(vec!["/api/login".into()]));
    let app = Route::new()
        .at("/api/me", Echo)
        .at("/api/login", Echo)
        .with(JwtMiddleware::new(a.clone()));

    let token = a.jwt().encode(&json!({"user_id": 7}), None).unwrap();
    let resp = app
        .call(
            Request::builder()
                .uri_str("/api/me")
                .header("Authorization", format!("Bearer {token}"))
                .finish(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), poem::http::StatusCode::OK);
    assert_eq!(resp.into_body().into_string().await.unwrap(), "user=7");

    // 401 响应头契约（钉住 content-type，防止将来被改成 web::Json 带 charset）
    let resp = app
        .call(Request::builder().uri_str("/api/me").finish())
        .await
        .unwrap();
    assert_eq!(resp.status(), poem::http::StatusCode::UNAUTHORIZED);
    assert_eq!(resp.content_type(), Some("application/json"));

    // 未匹配路径：.with 覆盖全部请求 → 无 token 401（对应新增 Note）
    let resp = app
        .call(Request::builder().uri_str("/api/nope").finish())
        .await
        .unwrap();
    assert_eq!(resp.status(), poem::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_is_401_with_message() {
    let a = Arc::new(auth(vec![]));
    let ep = JwtMiddleware::new(a.clone()).transform(Echo);
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // encode 产不出已过期令牌：exp 恒被覆写为 now + 有效期（encode_with_exp_for_test 是 #[cfg(test)] pub(crate)，集成测试取不到），
    // 故用同一密钥/算法直签；本配置 iss/aud 为空、jti 非必需，decode 只校验签名与 exp。
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({"iss": "", "aud": "", "exp": n - 30, "nbf": n - 60, "iat": n - 60, "jti": "poem-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let req = Request::builder()
        .uri_str("/api/me")
        .header("Authorization", format!("Bearer {expired}"))
        .finish();
    let resp = ep.call(req).await.unwrap();
    assert_eq!(resp.status(), poem::http::StatusCode::UNAUTHORIZED);
    let body = resp.into_body().into_string().await.unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["msg"], "Token has expired");
}
