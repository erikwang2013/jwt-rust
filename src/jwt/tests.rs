// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
// jwt-rust - JWT authentication for Rust web frameworks
//! jwt 核心单元测试（自 jwt.rs 拆出，控制单文件行数）

use super::*;
use crate::config::JwtConfig;
use crate::storage::FileTokenStorage;
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

fn jwt(cfg: JwtConfig) -> Jwt {
    let storage = FileTokenStorage::new(Some(
        std::env::temp_dir().join(format!("jwt_rust_jwt_{}", std::process::id())),
    ))
    .unwrap();
    Jwt::new(cfg, std::sync::Arc::new(storage)).unwrap()
}

#[test]
fn rejects_short_secret_and_unknown_algorithm() {
    let storage = std::sync::Arc::new(
        FileTokenStorage::new(Some(std::env::temp_dir().join("jwt_rust_jwt_short"))).unwrap(),
    );
    assert!(matches!(
        Jwt::new(
            JwtConfig {
                secret_key: "short".into(),
                ..Default::default()
            },
            storage.clone()
        ),
        Err(JwtError::Config(_))
    ));
    assert!(matches!(
        Jwt::new(
            JwtConfig {
                secret_key: SECRET.into(),
                algorithm: "HS999".into(),
                ..Default::default()
            },
            storage
        ),
        Err(JwtError::Config(_))
    ));
}

#[test]
fn encode_writes_default_claims_and_overrides_user_values() {
    let j = jwt(cfg());
    let token = j
        .encode(&json!({"user_id": 1, "exp": 1, "jti": "usermade"}), None)
        .unwrap();
    let payload = j.decode(&token).unwrap();
    assert_eq!(payload["user_id"], 1);
    assert_eq!(payload["iss"], "test-iss");
    assert_eq!(payload["aud"], "test-aud");
    assert_ne!(payload["exp"], 1); // 默认声明覆盖用户同名值（PHP array_merge 后数组覆盖语义）
    assert_ne!(payload["jti"], "usermade");
    assert_eq!(payload["jti"].as_str().unwrap().len(), 32); // 16 随机字节 hex
    assert!(payload["iat"].is_number() && payload["nbf"].is_number());
}

#[test]
fn encode_respects_expire_and_refresh_token_type() {
    let j = jwt(cfg());
    let t = j.encode(&json!({"user_id": 1}), Some(10)).unwrap();
    let exp = j.decode(&t).unwrap()["exp"].as_i64().unwrap();
    assert!((exp - (now() + 10)).abs() <= 2);
    // token_type=refresh 且不传 expire → refresh_expire(7200)
    let r = j
        .encode(&json!({"user_id": 1, "token_type": "refresh"}), None)
        .unwrap();
    let rexp = j.decode_with(&r, true).unwrap()["exp"].as_i64().unwrap(); // payload_without_validation 属 Task 1.6，此处用 decode_with
    assert!((rexp - (now() + 7200)).abs() <= 2);
}

#[test]
fn decode_rejects_wrong_issuer_audience_and_refresh_token() {
    let j = jwt(cfg());
    let other = jwt(JwtConfig {
        secret_key: SECRET.into(),
        issuer: "other".into(),
        audience: "test-aud".into(),
        ..Default::default()
    });
    let token = j.encode(&json!({"user_id": 1}), None).unwrap();
    assert!(matches!(other.decode(&token), Err(JwtError::Invalid(m)) if m.contains("issuer")));

    let other_aud = jwt(JwtConfig {
        secret_key: SECRET.into(),
        issuer: "test-iss".into(),
        audience: "x".into(),
        ..Default::default()
    });
    assert!(
        matches!(other_aud.decode(&token), Err(JwtError::Invalid(m)) if m.contains("audience"))
    );

    let refresh = j.encode(&json!({"token_type": "refresh"}), None).unwrap();
    assert!(matches!(j.decode(&refresh), Err(JwtError::Invalid(m)) if m.contains("Refresh token")));
    assert!(j.decode_with(&refresh, true).is_ok());
}

#[test]
fn audience_array_membership_matches() {
    let j = jwt(cfg());
    let n = now();
    let mk = |aud: serde_json::Value| {
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &json!({"user_id": 1, "iss": "test-iss", "aud": aud, "exp": n + 60, "nbf": n, "iat": n}),
            &EncodingKey::from_secret(SECRET.as_bytes()),
        ).unwrap()
    };
    assert!(j.decode(&mk(json!(["a", "test-aud"]))).is_ok());
    assert!(
        matches!(j.decode(&mk(json!(["a", "b"]))), Err(JwtError::Invalid(m)) if m.contains("audience"))
    );
}

#[test]
fn leeway_tolerates_clock_skew() {
    let mut c = cfg();
    c.leeway = 30;
    let j = jwt(c);
    let past = j
        .encode_with_exp_for_test(&json!({"user_id": 1}), now() - 5)
        .unwrap();
    assert!(j.decode(&past).is_ok(), "leeway 30s 内过期 5s 的令牌应放行");
}

#[test]
fn aud_matches_array_and_string() {
    assert!(aud_matches(&json!({"aud": ["a", "b"]}), "b"));
    assert!(aud_matches(&json!({"aud": "b"}), "b"));
    assert!(!aud_matches(&json!({"aud": ["a"]}), "b"));
    assert!(!aud_matches(&json!({}), "b"));
}

#[test]
fn huge_expire_does_not_panic() {
    let j = jwt(cfg());
    assert!(j.encode(&json!({"user_id": 1}), Some(u64::MAX)).is_ok());
    assert!(
        j.encode(&json!({"user_id": 1}), Some(i64::MAX as u64))
            .is_ok()
    ); // as i64 前修正会在此溢出 panic
}

#[test]
fn non_string_jti_is_rejected() {
    let j = jwt(cfg());
    let n = now();
    let t = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &json!({"iss": "test-iss", "aud": "test-aud", "exp": n + 60, "jti": [1, 2]}),
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    assert!(matches!(j.decode(&t), Err(JwtError::Invalid(m)) if m.contains("jti")));
}

#[test]
fn null_jti_is_accepted_like_php_isset() {
    let j = jwt(cfg());
    let n = now();
    let t = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &json!({"iss": "test-iss", "aud": "test-aud", "exp": n + 60, "jti": null}),
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .unwrap();
    assert!(j.decode(&t).is_ok()); // PHP isset($payload['jti'])：null 等同缺失，跳过黑名单检查
}

#[test]
fn encode_with_header_ignores_caller_alg() {
    let j = jwt(cfg());
    let t = j
        .encode_with_header(&json!({"user_id": 1}), None, Header::new(Algorithm::HS512))
        .unwrap();
    assert_eq!(
        jsonwebtoken::decode_header(&t).unwrap().alg,
        Algorithm::HS256
    );
    assert!(j.decode(&t).is_ok());
}

#[test]
fn decode_as_validate_and_send_sync() {
    #[derive(serde::Deserialize)]
    struct Claims {
        user_id: i64,
    }
    #[derive(serde::Deserialize)]
    #[allow(dead_code)] // 字段只为触发 serde 缺字段错误，从不读取
    struct Wrong {
        nope: String,
    }
    let j = jwt(cfg());
    let t = j.encode(&json!({"user_id": 42}), None).unwrap();
    assert_eq!(j.decode_as::<Claims>(&t).unwrap().user_id, 42);
    assert!(matches!(j.decode_as::<Wrong>(&t), Err(JwtError::Invalid(m)) if m.contains("claims")));
    assert!(j.validate(&t));
    assert!(!j.validate("garbage"));

    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Jwt>();
    assert_send_sync::<JwtPayload>();
}

// 测试专用一次性 RSA 密钥（openssl 现场生成，非机密）
const RSA_PRIVATE_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2cdMjktzqt1SF
77E5Hv/mL8nzWqINld6CTC8UwSog/mXEcPAxByMcTYTX1phqSFUeioNuB7AGWyaW
LSNhdh1oF37rHFGjs3uilpbMP17mMzx/O7Z6tf0J6hLoNGDp62180A4f1Nfa3aNM
+GdyakOsIgr0JvcaLE59fVq8H+kDSXkQ1H9EpTFiQ7GZjrL5OLEfPptywcr+fJnG
RuVEFBCeumtBQ7zlHUh/bkHkmBRwb99WhhALqmaHirRxcj4pw/MWZdWGimO53rfk
9ByR61jJA7W0KQh7IhpVBp+PERSBBnLj/Ib59kEqiqzlbiM7f8MYzs7DvCVN57Nd
b7iIl1FhAgMBAAECggEADl8gBTTb7yda4qQTf07oVI8eJuvUSSKtoPD0Ynum4Gt5
w8Qrv4jy5JdcqA3w+qpQ/jNmEAROAuoqO3k5yMMfpOP47PdRnQYV7qRTI6q4RITz
togTI05zrNTCAYWivrp7aPIQssQ27rg31WfZ6kLhqs0RtNLe8zJbSnpV6+zNk6MT
LEG46WOcl3DKlMkUR7vAireQzpuFv1QIJ7ZplOfkNZmob+fJFjb4M8vwD7l8+mKH
FXPXJJWLMK5o80CJS5bqT/cvgSiP9MEoXuMODtgfMKIfYG5QD6CejQzU6mb5F6U9
ijz0kLfHeZzff9NWyEYTXQUaVLj2jYTotFXHUh1DeQKBgQD2pXV1RHlldeYXCdHt
IoxYom+jZiLYqEeRmjcVDw4cRFeqmc6CeW11cnVURkr2wjEeavOVFxO40zb8tbIJ
cZJsyDi+De2Id0xICqIVpKU5hNMXMsY54DTPdq3d1r+EpACKk7EyZIYwc6mqUY2r
tMXG+OCZPD7ASGNR+WO2FTbQtQKBgQC9XRH4aoMfZxpJVPebLVPKvZ16gfrwtS4K
cOlxLhUMZ2JtqjL0J2acfYGZzlM65P2L4uw7A9PoFWQsrfdFf7oFgWaqT2BtZ/S9
W3PGUXVUHWvNadJ0p6MsfLzgmhmaDEOpHUSe9S0DIexJLoBb+W50eJJHlozT5uxI
I2JvNAxlfQKBgQC6pTcfiLO8/d0irgG4S56dLD8DDbVs8ttF6cepHf11kpostbu6
rJ0SdY0oOxFbblSxSgoOVqpMATnpPq39y34c599Yoz2POYf2NGW3ryKBRmxfb8Ll
5S7RmGO2Ll47x8fJFj7PfZa2b7CC/LgSqffIvGlqTFbIN39Bd1HnZmJWyQKBgFzF
OueT7vc0gLlKah/Y3gMmT/9TrIe+i3bMCGHNbLxt7dfCGUJqByhFiHe8kCP7SYf9
vTPQVUGPMUt+UvT2dUD7OzvWtWwEEO+v3RFcmPmDjGvPGy7Rbex+k94JQN+qgH9a
emLRxKKTPPpBUNs+YPGonCl8RTQPHtTcmP3X5vbVAoGBANIdbF7+wZR4n9akanif
wl6v4jPNXg6PlFS+JASE8dVugde/Mn1Jv+jz/s3jXso2zkVxVviRT/O16Ro9Zx2z
L+uV0sZ6STbfVBIFLzEYcMz9MUJ/jA2W7ykP4/FNB2TL3Tym93OOuI+RphyLmNhR
Sw3na8qRizD49Ms7vnIqjhYg
-----END PRIVATE KEY-----
";
const RSA_PUBLIC_PEM: &str = r"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtnHTI5Lc6rdUhe+xOR7/
5i/J81qiDZXegkwvFMEqIP5lxHDwMQcjHE2E19aYakhVHoqDbgewBlsmli0jYXYd
aBd+6xxRo7N7opaWzD9e5jM8fzu2erX9CeoS6DRg6ettfNAOH9TX2t2jTPhncmpD
rCIK9Cb3GixOfX1avB/pA0l5ENR/RKUxYkOxmY6y+TixHz6bcsHK/nyZxkblRBQQ
nrprQUO85R1If25B5JgUcG/fVoYQC6pmh4q0cXI+KcPzFmXVhopjud635PQcketY
yQO1tCkIeyIaVQafjxEUgQZy4/yG+fZBKoqs5W4jO3/DGM7Ow7wlTeezXW+4iJdR
YQIDAQAB
-----END PUBLIC KEY-----
";

#[test]
fn rs256_roundtrip_and_public_key_rejected() {
    let c = JwtConfig {
        secret_key: RSA_PRIVATE_PEM.into(),
        algorithm: "RS256".into(),
        issuer: "test-iss".into(),
        audience: "test-aud".into(),
        ..Default::default()
    };
    let j = jwt(c);
    let t = j.encode(&json!({"user_id": 1}), None).unwrap();
    assert_eq!(j.decode(&t).unwrap()["user_id"], 1);

    let storage = std::sync::Arc::new(
        FileTokenStorage::new(Some(std::env::temp_dir().join("jwt_rust_jwt_rsa_pub"))).unwrap(),
    );
    // 传公钥 PEM 须在启动期即报 Config（Jwt 无 Debug，故不用 unwrap_err）
    assert!(matches!(
        Jwt::new(
            JwtConfig {
                secret_key: RSA_PUBLIC_PEM.into(),
                algorithm: "RS256".into(),
                ..Default::default()
            },
            storage
        ),
        Err(JwtError::Config(_))
    ));
}

#[test]
fn refresh_rotates_and_blacklists_old_jti() {
    let j = jwt(cfg());
    let old = j
        .encode(&json!({"user_id": 1, "token_type": "refresh"}), Some(60))
        .unwrap();
    let old_payload = j.decode_with(&old, true).unwrap();

    let new = j.refresh(&old, None).unwrap();
    let new_payload = j.decode_with(&new, true).unwrap();
    assert_ne!(new_payload["jti"], old_payload["jti"]);
    assert_eq!(new_payload["user_id"], 1);
    assert_eq!(new_payload["token_type"], "refresh"); // 类型保留
    assert!((new_payload["exp"].as_i64().unwrap() - (now() + 7200)).abs() <= 2); // 默认 refresh_expire

    // 旧令牌已入黑名单：再刷新/当 refresh 用全部被拒
    assert!(matches!(
        j.decode_with(&old, true),
        Err(JwtError::Blacklisted)
    ));
    assert!(matches!(j.refresh(&old, None), Err(JwtError::Blacklisted)));
}

#[test]
fn refresh_rejects_access_token() {
    let j = jwt(cfg());
    let access = j.encode(&json!({"user_id": 1}), None).unwrap();
    assert!(
        matches!(j.refresh(&access, None), Err(JwtError::Invalid(m)) if m.contains("Only refresh tokens"))
    );
}

#[test]
fn blacklist_then_decode_is_rejected_idempotently() {
    let j = jwt(cfg());
    let t = j.encode(&json!({"user_id": 1}), Some(60)).unwrap();
    assert!(!j.is_blacklisted(&t));
    assert!(j.blacklist(&t).unwrap());
    assert!(j.is_blacklisted(&t));
    assert!(j.blacklist(&t).unwrap()); // 幂等
    assert!(matches!(j.decode(&t), Err(JwtError::Blacklisted)));
}

#[test]
fn blacklist_expired_token_takes_unvalidated_path() {
    let dir = std::env::temp_dir().join(format!("jwt_rust_jwt_blk_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir); // 先清空：pid 复用时的旧残留会造成假红，而非假绿
    let storage = Arc::new(
        FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(0.0),
    );
    let j = Jwt::new(cfg(), storage).unwrap();
    // 过期令牌须带 jti 才有可记录对象（同 PHP：无 jti 时 blacklist 返 false）
    let past = j
        .encode_with_exp_for_test(&json!({"user_id": 1, "jti": "expired-jti"}), now() - 5)
        .unwrap();
    // Expired → 无验证补写路径；FileTokenStorage 对已过期条目跳过落盘（同 PHP）但返回 true
    assert!(j.blacklist(&past).unwrap());
    // 目录须为空：jti 非 hex 时文件名是 hex 编码，故按文件数断言而非按 "expired-jti.json" 猜名
    let written: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        written.is_empty(),
        "file 驱动对过期条目不落盘（同 PHP），实际: {written:?}"
    );
}

#[test]
fn blacklist_without_jti_or_exp_returns_false() {
    let j = jwt(cfg());
    let n = now();
    let mk = |claims: serde_json::Value| {
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap()
    };
    // 面 1：有效令牌但无 jti → Ok 路径 → Ok(false)
    let t = mk(json!({"iss": "test-iss", "aud": "test-aud", "exp": n + 60}));
    assert!(!j.blacklist(&t).unwrap());

    // 面 2：jti 已拉黑且无 exp → Blacklisted 后走补写路径，缺 exp → Ok(false)
    let t2 = mk(json!({"iss": "test-iss", "aud": "test-aud", "exp": n + 60, "jti": "b2"}));
    assert!(j.blacklist(&t2).unwrap()); // 前置：确有拉黑，否则面 2 走的是 Ok 路径
    let t3 = mk(json!({"iss": "test-iss", "aud": "test-aud", "jti": "b2"}));
    assert!(!j.blacklist(&t3).unwrap());
}

#[test]
fn payload_without_validation_strips_non_string_jti() {
    let j = jwt(cfg());
    let t = j.encode(&json!({"user_id": 1}), None).unwrap();
    let p = j.payload_without_validation(&t).unwrap();
    assert_eq!(p["user_id"], 1);
    assert!(matches!(
        j.payload_without_validation("not.a.token"),
        Err(JwtError::Invalid(_))
    ));
    // 伪造 jti 为数组 → 剔除，不炸存储层
    let forged = format!(
        "{}.{}.{}",
        base64url(br#"{"alg":"HS256"}"#),
        base64url(br#"{"jti":[1,2],"user_id":9}"#),
        "sig"
    );
    let p2 = j.payload_without_validation(&forged).unwrap();
    assert!(p2.get("jti").is_none());
    assert_eq!(p2["user_id"], 9);
    assert!(matches!(
        j.payload_without_validation(""),
        Err(JwtError::Invalid(_))
    ));
    assert!(matches!(
        j.payload_without_validation("a.b.c.d"),
        Err(JwtError::Invalid(_))
    ));
    // 非对象 body（合法 JSON 标量）→ 空对象（不 panic，同 PHP json_decode 非数组返 []）
    let nonobj = format!(
        "{}.{}.{}",
        base64url(br#"{"alg":"HS256"}"#),
        base64url(b"123"),
        "sig"
    );
    assert_eq!(j.payload_without_validation(&nonobj).unwrap(), json!({}));
}

#[test]
fn bearer_token_forms() {
    assert_eq!(bearer_token("Bearer abc"), Some("abc".into()));
    assert_eq!(bearer_token("bearer   abc  "), Some("abc".into()));
    assert_eq!(bearer_token("Basic abc"), None);
    assert_eq!(bearer_token("Bearer "), None);
    assert_eq!(bearer_token("Bear"), None);
    assert_eq!(bearer_token("日本語日本語"), None); // 第 7 字节落在字符中间：split_at_checked 不得 panic
}

#[test]
fn fail_open_releases_on_storage_error() {
    struct Down; // 永远失败的存储
    impl TokenStorage for Down {
        fn blacklist(&self, _: &str, _: i64) -> Result<bool, JwtError> {
            Err(JwtError::Storage("down".into()))
        }
        fn is_blacklisted(&self, _: &str) -> Result<bool, JwtError> {
            Err(JwtError::Storage("down".into()))
        }
        fn cleanup(&self) -> Result<bool, JwtError> {
            Err(JwtError::Storage("down".into()))
        }
    }
    let mut c = cfg();
    c.storage.fail_open = false;
    let closed = Jwt::new(c.clone(), std::sync::Arc::new(Down)).unwrap();
    let t = closed.encode(&json!({"user_id": 1}), None).unwrap();
    assert!(matches!(closed.decode(&t), Err(JwtError::Storage(_))));

    c.storage.fail_open = true;
    let open = Jwt::new(c, std::sync::Arc::new(Down)).unwrap();
    assert!(open.decode(&t).is_ok());
}

#[test]
fn expired_beyond_leeway_is_rejected() {
    let j = jwt(cfg()); // leeway 默认 0
    let past = j
        .encode_with_exp_for_test(&json!({"user_id": 1}), now() - 30)
        .unwrap();
    assert!(matches!(j.decode(&past), Err(JwtError::Expired)));
}

fn base64url(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
