// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "warp")]
use std::sync::Arc;

use serde_json::json;
// 组合子 `.and/.map/.recover` 均由 warp::Filter 提供，须在作用域内（任务书片段遗漏）
use warp::Filter;

use jwt_rust::config::JwtConfig;
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::warp::{JwtRejection, with_jwt};
use jwt_rust::jwt::JwtPayload;

fn auth(except: Vec<String>) -> Arc<JwtAuth> {
    Arc::new(
        JwtAuth::from_config(JwtConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            middleware: jwt_rust::config::MiddlewareConfig { except },
            ..Default::default()
        })
        .unwrap(),
    )
}

#[tokio::test]
async fn filter_flow() {
    let a = auth(vec![]);
    let route = warp::path!("me")
        .and(with_jwt(a.clone()))
        .map(|p: JwtPayload| format!("user={}", p.get("user_id").unwrap()))
        .recover(|rej: warp::Rejection| async move {
            match rej.find::<JwtRejection>() {
                Some(j) => Ok(warp::reply::with_status(
                    warp::reply::json(&j.body),
                    j.status,
                )),
                None => Err(rej),
            }
        });

    // 无 token → 401 三字段
    let resp = warp::test::request().path("/me").reply(&route).await;
    assert_eq!(resp.status(), 401);
    let v: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(v["code"], 401);
    assert_eq!(v["msg"], "Token not provided");
    assert!(v["data"].is_null());

    // 有效 token → 200
    let token = a.jwt().encode(&json!({"user_id": 7}), None).unwrap();
    let resp = warp::test::request()
        .path("/me")
        .header("Authorization", format!("Bearer {token}"))
        .reply(&route)
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(String::from_utf8_lossy(resp.body()), "user=7");
}

#[tokio::test]
async fn expired_token_is_401_with_message() {
    let a = auth(vec![]);
    let route = warp::path!("me")
        .and(with_jwt(a.clone()))
        .map(|_p: JwtPayload| "ok")
        .recover(|rej: warp::Rejection| async move {
            match rej.find::<JwtRejection>() {
                Some(j) => Ok(warp::reply::with_status(
                    warp::reply::json(&j.body),
                    j.status,
                )),
                None => Err(rej),
            }
        });
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // encode 产不出已过期令牌（exp 恒被覆写），故用同一密钥/算法直签；本配置 iss/aud 为空
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &json!({"iss": "", "aud": "", "exp": n - 30, "nbf": n - 60, "iat": n - 60, "jti": "warp-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let resp = warp::test::request()
        .path("/me")
        .header("Authorization", format!("Bearer {expired}"))
        .reply(&route)
        .await;
    assert_eq!(resp.status(), 401);
    let v: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(v["msg"], "Token has expired");
}

#[tokio::test]
async fn except_path_is_explicit_rejection() {
    let a = auth(vec!["/public".into()]);
    let route = warp::path!("public")
        .and(with_jwt(a))
        .map(|_p: JwtPayload| "ok")
        .recover(|rej: warp::Rejection| async move {
            match rej.find::<JwtRejection>() {
                Some(j) => Ok(warp::reply::with_status(
                    warp::reply::json(&j.body),
                    j.status,
                )),
                None => Err(rej),
            }
        });
    let resp = warp::test::request().path("/public").reply(&route).await;
    assert_eq!(resp.status(), 500); // 用法错误：except 路径不得挂 with_jwt
    let v: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(v["code"], 500);
}
