// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
// jwt-rust - JWT authentication for Rust web frameworks
//! 安全负路径回归锁（篡改签名 / 算法混淆 / future nbf / 无 exp 登出 / 启动期密钥与 leeway 校验）。

use super::*;
use crate::config::JwtConfig;
use crate::storage::FileTokenStorage;
use base64::Engine as _;
use serde_json::json;

const SECRET: &str = "0123456789abcdef0123456789abcdef"; // 32 字节

fn cfg() -> JwtConfig {
    JwtConfig {
        secret_key: SECRET.into(),
        issuer: "test-iss".into(),
        audience: "test-aud".into(),
        ..Default::default()
    }
}

fn try_new(cfg: JwtConfig, tag: &str) -> Result<Jwt, JwtError> {
    let storage = std::sync::Arc::new(
        FileTokenStorage::new(Some(
            std::env::temp_dir().join(format!("jwt_rust_security_{tag}_{}", std::process::id())),
        ))
        .unwrap(),
    );
    Jwt::new(cfg, storage)
}

fn jwt(cfg: JwtConfig) -> Jwt {
    try_new(cfg, "core").unwrap()
}

fn sign(alg: Algorithm, claims: serde_json::Value) -> String {
    jsonwebtoken::encode(
        &Header::new(alg),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn leeway_over_max_is_rejected_at_startup() {
    // 边界值可用
    assert!(
        try_new(
            JwtConfig {
                leeway: 86_400,
                ..cfg()
            },
            "lw_ok"
        )
        .is_ok()
    );
    // 3.65e9 ≈ 把"1 小时"按纳秒写：jsonwebtoken 内部 u64 减法下溢（debug panic / release 全量过期）
    let Err(e) = try_new(
        JwtConfig {
            leeway: 3_650_000_000,
            ..cfg()
        },
        "lw_bad",
    ) else {
        panic!("leeway above the cap must be a config error");
    };
    assert!(matches!(e, JwtError::Config(_)), "got {e:?}");
}

#[test]
fn pem_secret_rejected_for_hmac_algorithms() {
    // 算法误配：RSA 公钥（本就公开）粘进 secret_key 而 algorithm 缺省为 HS256 → 公钥即密钥，人人可伪造
    let c = JwtConfig {
        secret_key: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n".into(),
        ..cfg()
    };
    let Err(e) = try_new(c, "pem") else {
        panic!("PEM material with an HMAC algorithm must be rejected at startup");
    };
    assert!(matches!(e, JwtError::Config(_)), "got {e:?}");
}

#[test]
fn hs512_token_rejected_by_hs256_instance() {
    // 算法收敛回归锁：header.alg 不在 Validation 白名单时 jsonwebtoken 直接拒绝
    let j = jwt(cfg());
    let n = now();
    let t = sign(
        Algorithm::HS512,
        json!({"iss": "test-iss", "aud": "test-aud", "exp": n + 60, "nbf": n, "iat": n}),
    );
    assert!(matches!(j.decode(&t), Err(JwtError::Invalid(m)) if m.contains("InvalidAlgorithm")));
}

#[test]
fn alg_none_token_is_rejected() {
    let j = jwt(cfg());
    let n = now();
    let header = b64(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = b64(
        json!({"iss": "test-iss", "aud": "test-aud", "exp": n + 60, "nbf": n, "jti": "none"})
            .to_string()
            .as_bytes(),
    );
    let t = format!("{header}.{payload}.");
    assert!(matches!(j.decode(&t), Err(JwtError::Invalid(_))));
}

#[test]
fn tampered_payload_is_rejected() {
    let j = jwt(cfg());
    let t = j.encode(&json!({"user_id": 1}), Some(60)).unwrap();
    let parts: Vec<&str> = t.split('.').collect();
    let mut claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap(),
    )
    .unwrap();
    claims["user_id"] = json!(2); // 改内容、不改签名
    let forged = format!(
        "{}.{}.{}",
        parts[0],
        b64(claims.to_string().as_bytes()),
        parts[2]
    );
    assert!(
        matches!(j.decode(&forged), Err(JwtError::Invalid(m)) if m.contains("InvalidSignature"))
    );
}

#[test]
fn future_nbf_is_rejected() {
    // validate_nbf = true 回归锁（jsonwebtoken 默认 false，删掉这行配置必须测试变红）
    let j = jwt(cfg());
    let n = now();
    let t = sign(
        Algorithm::HS256,
        json!({"iss": "test-iss", "aud": "test-aud", "exp": n + 3600, "nbf": n + 300, "iat": n}),
    );
    assert!(matches!(j.decode(&t), Err(JwtError::Invalid(m)) if m.contains("Immature")));
}

#[test]
fn blacklist_token_without_exp_is_explicit_error() {
    // 外部签发、无 exp 的令牌：decode 放行（宽松校验），但登出必须显式失败而非假成功
    let j = jwt(cfg());
    let t = sign(
        Algorithm::HS256,
        json!({"iss": "test-iss", "aud": "test-aud", "iat": now(), "jti": "noexp-e2e"}),
    );
    assert!(j.decode(&t).is_ok());
    let Err(e) = j.blacklist(&t) else {
        panic!("blacklisting an exp-less token must not report success");
    };
    assert!(
        matches!(e, JwtError::Invalid(ref m) if m.contains("no exp")),
        "got {e:?}"
    );
    assert!(!j.is_blacklisted(&t)); // 关键证据：什么都没被记录
}
