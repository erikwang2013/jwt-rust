// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "salvo")]
// 用 salvo 自带 TestClient（salvo 1.0.1 default features 含 `test`，无需改 Cargo.toml）。
use salvo::prelude::*;
use salvo::test::{ResponseExt, TestClient};

use jwt_rust::config::JwtConfig;
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::salvo::JwtHoop;
use jwt_rust::jwt::JwtPayload;

fn auth(except: Vec<String>) -> JwtAuth {
    JwtAuth::from_config(JwtConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        middleware: jwt_rust::config::MiddlewareConfig { except },
        ..Default::default()
    })
    .unwrap()
}

#[handler]
async fn me(depot: &mut Depot, res: &mut Response) {
    // get_typed：1.0.1 起 obtain 为 deprecated 别名
    let user = depot
        .get_typed::<JwtPayload>()
        .map(|p| p.get("user_id").unwrap().to_string())
        .unwrap_or_else(|_| "none".into());
    res.render(Text::Plain(format!("user={user}")));
}

#[handler]
async fn login(res: &mut Response) {
    res.render(Text::Plain("public"));
}

fn service() -> (Service, std::sync::Arc<JwtAuth>) {
    let a = std::sync::Arc::new(auth(vec!["/api/login".into()]));
    let router = Router::new()
        .hoop(JwtHoop::new(a.clone()))
        .push(Router::with_path("api/me").get(me))
        .push(Router::with_path("api/login").get(login));
    (Service::new(router), a)
}

#[tokio::test]
async fn hoop_flow() {
    let (service, a) = service();

    // 无 token → 401 JSON（三字段）
    let mut resp = TestClient::get("http://127.0.0.1:5800/api/me")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
    // 401 响应头契约（钉住 content-type，与其余适配层一致、不带 charset）
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let v: serde_json::Value = resp.take_json().await.unwrap();
    assert_eq!(v["code"], 401);
    assert_eq!(v["msg"], "Token not provided");
    assert!(v["data"].is_null());

    // 有效 token → 200 + payload（depot）
    let token = a
        .jwt()
        .encode(&serde_json::json!({"user_id": 7}), None)
        .unwrap();
    let mut resp = TestClient::get("http://127.0.0.1:5800/api/me")
        .add_header("Authorization", format!("Bearer {token}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    assert_eq!(resp.take_string().await.unwrap(), "user=7");

    // except 路径无 token 放行
    let mut resp = TestClient::get("http://127.0.0.1:5800/api/login")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::OK));
    assert_eq!(resp.take_string().await.unwrap(), "public");
}

#[tokio::test]
async fn unmatched_path_stays_404_with_router_hoop() {
    let (service, _) = service();
    // Router::hoop 只在路由匹配成功时运行（Router::detect 沿匹配栈收集 hoops），无 token 也不得 401
    let resp = TestClient::get("http://127.0.0.1:5800/nonexistent")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::NOT_FOUND));
    // 路径匹配但方法不匹配 → 405（同样不经 hoop）
    let resp = TestClient::post("http://127.0.0.1:5800/api/me")
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::METHOD_NOT_ALLOWED));
}

#[tokio::test]
async fn expired_token_is_401_with_message() {
    let (service, _) = service();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // encode 产不出已过期令牌（exp 恒被覆写），故用同一密钥/算法直签；本配置 iss/aud 为空，decode 只校验签名与 exp
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({"iss": "", "aud": "", "exp": n - 30, "nbf": n - 60, "iat": n - 60, "jti": "salvo-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let mut resp = TestClient::get("http://127.0.0.1:5800/api/me")
        .add_header("Authorization", format!("Bearer {expired}"), true)
        .send(&service)
        .await;
    assert_eq!(resp.status_code, Some(StatusCode::UNAUTHORIZED));
    let v: serde_json::Value = resp.take_json().await.unwrap();
    assert_eq!(v["msg"], "Token has expired");
}
