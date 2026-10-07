// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "rocket")]
use rocket::http::{Header, Status};
use rocket::local::blocking::Client;
use serde_json::json;

use jwt_rust::config::JwtConfig;
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::rocket::{JwtGuard, jwt_unauthorized};

#[rocket::get("/me")]
fn me(p: JwtGuard) -> String {
    format!("user={}", p.0.get("user_id").unwrap())
}

#[rocket::get("/open")]
fn open() -> &'static str {
    "public"
}

#[rocket::get("/own401")]
fn own401() -> Status {
    Status::Unauthorized
}

fn auth() -> JwtAuth {
    JwtAuth::from_config(JwtConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        ..Default::default()
    })
    .unwrap()
}

fn client() -> (Client, JwtAuth) {
    let auth = auth();
    let rocket = rocket::build()
        .manage(std::sync::Arc::new(auth.clone()))
        .register("/", rocket::catchers![jwt_unauthorized])
        .mount("/", rocket::routes![me, open, own401]);
    (Client::untracked(rocket).unwrap(), auth)
}

#[test]
fn guard_flow() {
    let (client, auth) = client();
    // 无 token → 401 + JSON 体（渲染者是 catcher jwt_unauthorized；守卫 Error 里的 JwtRejection 被 rocket 丢弃）
    let resp = client.get("/me").dispatch();
    assert_eq!(resp.status(), Status::Unauthorized);
    let v: serde_json::Value = serde_json::from_str(&resp.into_string().unwrap()).unwrap();
    assert_eq!(v["code"], 401);
    assert_eq!(v["msg"], "Token not provided");
    assert!(v["data"].is_null());

    // 有效 token → 200
    let token = auth.jwt().encode(&json!({"user_id": 7}), None).unwrap();
    let resp = client
        .get("/me")
        .header(Header::new("Authorization", format!("Bearer {token}")))
        .dispatch();
    assert_eq!(resp.status(), Status::Ok);
    assert_eq!(resp.into_string().unwrap(), "user=7");

    // 未挂 guard 的路由天然公开（rocket 的 except 语义：按路由选择）
    let resp = client.get("/open").dispatch();
    assert_eq!(resp.status(), Status::Ok);
}

#[test]
fn expired_token_is_401_with_message() {
    let (client, _) = client();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // encode 会覆写 exp，直签一枚已过期令牌（镜像 encode 写入的 claims 结构）
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({"iss": "", "aud": "", "exp": n - 30, "nbf": n - 60, "iat": n - 60, "jti": "rocket-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let resp = client
        .get("/me")
        .header(Header::new("Authorization", format!("Bearer {expired}")))
        .dispatch();
    assert_eq!(resp.status(), Status::Unauthorized);
    let v: serde_json::Value = serde_json::from_str(&resp.into_string().unwrap()).unwrap();
    assert_eq!(v["msg"], "Token has expired");
}

/// 锁死集成要求：守卫失败只送出 Status（rocket 丢弃 Error 值），统一 JSON 体必须靠 catcher；
/// 若日后 rocket 改为调用 Error 的 Responder，本测试会失败并提示简化适配层。
#[test]
fn without_catcher_401_keeps_rocket_default_body() {
    let rocket = rocket::build()
        .manage(std::sync::Arc::new(auth()))
        .mount("/", rocket::routes![me]);
    let client = Client::untracked(rocket).unwrap();
    let resp = client.get("/me").dispatch();
    assert_eq!(resp.status(), Status::Unauthorized);
    assert!(serde_json::from_str::<serde_json::Value>(&resp.into_string().unwrap()).is_err());
}

/// catcher 注册在 "/" → 非守卫来源的 401 也被改写成统一 JSON 体，走兜底文案
#[test]
fn non_guard_401_is_taken_over_by_catcher_with_fallback_message() {
    let (client, _) = client();
    let resp = client.get("/own401").dispatch();
    assert_eq!(resp.status(), Status::Unauthorized);
    let v: serde_json::Value = serde_json::from_str(&resp.into_string().unwrap()).unwrap();
    assert_eq!(v["code"], 401);
    assert_eq!(v["msg"], "Token authentication failed"); // 非守卫来源 → 兜底文案（doc 已承诺）
}
