// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "actix")]
use actix_web::{App, HttpMessage, HttpRequest, HttpResponse, test, web};
use serde_json::json;

use jwt_rust::config::JwtConfig;
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::actix::Jwt;
use jwt_rust::jwt::JwtPayload;

fn auth(except: Vec<String>) -> JwtAuth {
    JwtAuth::from_config(JwtConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        middleware: jwt_rust::config::MiddlewareConfig { except },
        ..Default::default()
    })
    .unwrap()
}

async fn me(req: HttpRequest) -> HttpResponse {
    match req.extensions().get::<JwtPayload>() {
        Some(p) => HttpResponse::Ok().body(format!("user={}", p.get("user_id").unwrap())),
        None => HttpResponse::Ok().body("none"),
    }
}

async fn login() -> HttpResponse {
    HttpResponse::Ok().body("public")
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[actix_web::test]
async fn jwt_middleware_flow() {
    let a = std::sync::Arc::new(auth(vec!["/api/login".into()]));
    let app = test::init_service(
        App::new()
            .wrap(Jwt::new(a.clone()))
            .route("/api/me", web::get().to(me))
            .route("/api/login", web::get().to(login)),
    )
    .await;

    // 无 token → 401 JSON
    let req = test::TestRequest::get().uri("/api/me").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["code"], 401);
    assert_eq!(body["msg"], "Token not provided");
    assert!(body["data"].is_null());

    // 有效 token → 200 + payload
    let token = a.jwt().encode(&json!({"user_id": 7}), None).unwrap();
    let req = test::TestRequest::get()
        .uri("/api/me")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let text = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert_eq!(text, "user=7");

    // except 路径无 token 放行
    let req = test::TestRequest::get().uri("/api/login").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let text = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
    assert_eq!(text, "public");
}

#[actix_web::test]
async fn expired_token_is_401_with_message() {
    let a = std::sync::Arc::new(auth(vec![]));
    let app = test::init_service(
        App::new()
            .wrap(Jwt::new(a.clone()))
            .route("/api/me", web::get().to(me)),
    )
    .await;
    let n = now_secs();
    // encode 会覆写 exp，直签一枚已过期令牌（镜像 encode 写入的 claims 结构）
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({"iss": "", "aud": "", "exp": n - 30, "nbf": n - 60, "iat": n - 60, "jti": "actix-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let req = test::TestRequest::get()
        .uri("/api/me")
        .insert_header(("Authorization", format!("Bearer {expired}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["msg"], "Token has expired");
}

#[actix_web::test]
async fn unmatched_path_is_401_with_wrap() {
    let a = std::sync::Arc::new(auth(vec![]));
    let app = test::init_service(
        App::new()
            .wrap(Jwt::new(a.clone()))
            .route("/api/me", web::get().to(me)),
    )
    .await;
    let req = test::TestRequest::get().uri("/nope").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401); // wrap 覆盖所有请求：未匹配路径同样鉴权（actix 无 route_layer，Note 已承诺）
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["code"], 401);
}
