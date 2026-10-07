// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! Native (framework-less) request guard, mirroring the PHP Native\Guard.

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;

use crate::config::JwtConfig;
use crate::error::JwtError;
use crate::factory::JwtFactory;
use crate::jwt::Jwt;

/// 原生 Rust（无框架）请求守卫（对应 PHP Native\Guard）。
/// Rust 无全局请求对象：401 的"输出并结束"由调用方用 `unauthorized_body` 完成。
pub struct Guard {
    jwt: Arc<Jwt>,
}

impl Guard {
    pub fn new(jwt: Jwt) -> Self {
        Self { jwt: Arc::new(jwt) }
    }

    pub fn from_config(config: JwtConfig) -> Result<Self, JwtError> {
        Ok(Self::new(JwtFactory::from_config(config)?))
    }

    pub fn from_env() -> Result<Self, JwtError> {
        Ok(Self::new(JwtFactory::from_env()?))
    }

    /// 从 TOML 配置文件组装守卫（对应 PHP Native\Guard::fromFile）
    pub fn from_file(path: &Path) -> Result<Self, JwtError> {
        Ok(Self::new(JwtFactory::from_file(path)?))
    }

    /// 校验并返回 payload；token=None 时抛"未携带令牌"
    pub fn authenticate(&self, token: Option<&str>) -> Result<Value, JwtError> {
        let token = token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| JwtError::invalid("Token not provided"))?;
        self.jwt.decode(token)
    }

    pub fn check(&self, token: Option<&str>) -> bool {
        self.authenticate(token).is_ok()
    }

    /// 入口脚本语义：失败时本方法不输出任何内容，由调用方用 `unauthorized_body` 生成并写出 401 响应体
    pub fn require_auth(&self, token: Option<&str>) -> Result<Value, JwtError> {
        self.authenticate(token)
    }

    pub fn jwt(&self) -> &Jwt {
        &self.jwt
    }
}

/// 与八框架适配层完全一致的 401 响应体（{"code":401,"msg":…,"data":null}）
pub fn unauthorized_body(err: &JwtError) -> Value {
    serde_json::json!({ "code": 401, "msg": err.user_message(), "data": null })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_body_shape() {
        let v = unauthorized_body(&JwtError::Expired);
        assert_eq!(v["code"], 401);
        assert_eq!(v["msg"], "Token has expired");
        assert_eq!(v.get("data"), Some(&serde_json::Value::Null));
        assert_eq!(
            unauthorized_body(&JwtError::Storage("x".into()))["msg"],
            "Token authentication failed"
        );
    }

    #[test]
    fn authenticate_missing_token_is_invalid() {
        let g = Guard::from_config(JwtConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(
            matches!(g.authenticate(None), Err(JwtError::Invalid(m)) if m.contains("not provided"))
        );
        assert!(matches!(
            g.authenticate(Some("")),
            Err(JwtError::Invalid(_))
        ));
        assert!(!g.check(Some("garbage")));
    }

    #[test]
    fn guard_success_path() {
        let g = Guard::from_config(JwtConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            ..Default::default()
        })
        .unwrap();
        let token = g
            .jwt()
            .encode(&serde_json::json!({"sub": "u1"}), None)
            .unwrap();
        assert_eq!(g.authenticate(Some(&token)).unwrap()["sub"], "u1");
        assert!(g.check(Some(&token)));
        assert_eq!(g.require_auth(Some(&token)).unwrap()["sub"], "u1");
    }
}
