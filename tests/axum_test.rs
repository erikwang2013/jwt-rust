// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "axum")]
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use serde_json::json;
use tower::ServiceExt;

use jwt_rust::config::JwtConfig;
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::axum::JwtLayer;
use jwt_rust::jwt::JwtPayload;

fn app() -> (Router, JwtAuth) {
    let auth = JwtAuth::from_config(JwtConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        middleware: jwt_rust::config::MiddlewareConfig {
            except: vec!["/api/login".into()],
        },
        ..Default::default()
    })
    .unwrap();
    let router = Router::new()
        .route(
            "/api/me",
            get(|p: Option<axum::Extension<JwtPayload>>| async move {
                format!(
                    "user={}",
                    p.map(|e| e.0.get("user_id").unwrap().to_string())
                        .unwrap_or_default()
                )
            }),
        )
        .route("/api/login", get(|| async { "public" }))
        .layer(JwtLayer::new(Arc::new(auth.clone())));
    (router, auth)
}

#[tokio::test]
async fn missing_token_is_401_with_json_body() {
    let (app, _) = app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["code"], 401);
    assert_eq!(v["msg"], "Token not provided");
    assert!(v["data"].is_null());
}

#[tokio::test]
async fn valid_token_passes_payload_and_except_skips() {
    let (app, auth) = app();
    let token = auth.jwt().encode(&json!({"user_id": 7}), None).unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/me")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    assert_eq!(&body[..], b"user=7");

    // except 路径无 token 也放行
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
async fn garbage_or_wrong_scheme_token_is_401() {
    let (app, _) = app();
    for header in ["Bearer garbage", "Basic abc"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/me")
                    .header("Authorization", header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn attach_preserves_404_and_except_body() {
    let auth = JwtAuth::from_config(JwtConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        middleware: jwt_rust::config::MiddlewareConfig {
            except: vec!["/api/login".into()],
        },
        ..Default::default()
    })
    .unwrap();
    let app = JwtLayer::new(Arc::new(auth)).attach(
        Router::new()
            .route("/api/me", get(|| async { "ok" }))
            .route("/api/login", get(|| async { "public" })),
    );

    // attach(route_layer)：未匹配路径不被鉴权拦截，保持 404
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // except 路径无 token 放行且内容正确
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
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    assert_eq!(&body[..], b"public");
}

#[tokio::test]
async fn expired_token_is_401_with_message() {
    let (app, _) = app();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // encode 会覆写 exp，直签一枚已过期令牌（镜像 encode 写入的 claims 结构）
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({"iss": "", "aud": "", "exp": now - 30, "nbf": now - 60, "iat": now - 60, "jti": "e2e-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    ).unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/me")
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
