// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "ecat")]
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use serde_json::json;
use tower::ServiceExt;

use jwt_rust::config::JwtConfig;
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::ecat::JwtLayer;
use jwt_rust::jwt::JwtPayload;

fn auth() -> JwtAuth {
    JwtAuth::from_config(JwtConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        middleware: jwt_rust::config::MiddlewareConfig {
            except: vec!["/api/login".into()],
        },
        ..Default::default()
    })
    .unwrap()
}

#[tokio::test]
async fn layer_flow_like_ecat_middleware() {
    let a = Arc::new(auth());
    let app = Router::new()
        .route(
            "/me",
            get(|req: axum::http::Request<Body>| async move {
                let user = req
                    .extensions()
                    .get::<JwtPayload>()
                    .map(|p| p.get("user_id").unwrap().to_string())
                    .unwrap_or_else(|| "none".into());
                format!("user={user}")
            }),
        )
        .route("/api/login", get(|| async { "public" }))
        .layer(JwtLayer::new(a.clone()));

    // 无 token → 401 三字段
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/me").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["code"], 401);
    assert_eq!(v["msg"], "Token not provided");
    assert!(v["data"].is_null());

    // 有效 token → 200 + payload（e-cat 的 axum transport 同款用法）
    let token = a.jwt().encode(&json!({"user_id": 7}), None).unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/me")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    assert_eq!(&body[..], b"user=7");

    // except 路径放行
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn expired_token_is_401_with_message() {
    let a = Arc::new(auth());
    let app = Router::new()
        .route("/me", get(|| async { "ok" }))
        .layer(JwtLayer::new(a.clone()));
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // encode 产不出已过期令牌（exp 恒被覆写），故用同一密钥/算法直签
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({"iss": "", "aud": "", "exp": n - 30, "nbf": n - 60, "iat": n - 60, "jti": "ecat-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/me")
                .header("Authorization", format!("Bearer {expired}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["msg"], "Token has expired");
}
