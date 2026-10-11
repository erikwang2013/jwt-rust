// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
// jwt-rust - JWT authentication for Rust web frameworks
//! Stable error hierarchy with numeric codes 1-6 (public API).

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum JwtError {
    /// 令牌已过期（错误码 1）。
    #[error("Token has expired")]
    Expired,
    /// 令牌无效：签名 / 结构 / issuer / audience / 刷新令牌当访问令牌用等（错误码 2）。
    #[error("{0}")]
    Invalid(String),
    /// 令牌已进黑名单（错误码 3）。
    #[error("Token has been blacklisted")]
    Blacklisted,
    /// 黑名单存储层错误（错误码 4）。
    #[error("Storage error: {0}")]
    Storage(String),
    /// 配置错误，装配期报出（错误码 5）。
    #[error("Configuration error: {0}")]
    Config(String),
    /// 网络错误（错误码 6）。
    #[error("Network error: {0}")]
    Network(String),
}

impl JwtError {
    /// 稳定错误码（1-6），对外可按码分支
    #[must_use]
    pub fn code(&self) -> i32 {
        match self {
            Self::Expired => 1,
            Self::Invalid(_) => 2,
            Self::Blacklisted => 3,
            Self::Storage(_) => 4,
            Self::Config(_) => 5,
            Self::Network(_) => 6,
        }
    }

    #[must_use]
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Self::Expired | Self::Invalid(_) | Self::Blacklisted)
    }

    /// 对外安全文案：鉴权类返回具体原因，其余统一
    pub fn user_message(&self) -> String {
        if self.is_auth_failure() {
            self.to_string()
        } else {
            "Token authentication failed".to_string()
        }
    }

    // 构造函数（与变体一一对应）
    /// Construct an auth-failure error.
    ///
    /// `msg` is surfaced verbatim to end users via [`JwtError::user_message`]
    /// (it becomes the `msg` field of the unified 401 body). Pass audited,
    /// human-reviewed text only: never internal/IO error strings; engine
    /// errors that merely describe why the token is invalid (e.g.
    /// jsonwebtoken's `InvalidSignature`) may pass through. Must be
    /// non-empty.
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::Invalid(msg.into())
    }
    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }
    pub fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        assert_eq!(JwtError::Expired.code(), 1);
        assert_eq!(JwtError::Invalid("x".into()).code(), 2);
        assert_eq!(JwtError::Blacklisted.code(), 3);
        assert_eq!(JwtError::Storage("x".into()).code(), 4);
        assert_eq!(JwtError::Config("x".into()).code(), 5);
        assert_eq!(JwtError::Network("x".into()).code(), 6);
    }

    #[test]
    fn user_message_hides_non_auth_errors() {
        assert_eq!(JwtError::Expired.user_message(), "Token has expired");
        assert_eq!(
            JwtError::Blacklisted.user_message(),
            "Token has been blacklisted"
        );
        assert_eq!(
            JwtError::Storage("conn refused".into()).user_message(),
            "Token authentication failed"
        );
        assert_eq!(
            JwtError::Config("bad key".into()).user_message(),
            "Token authentication failed"
        );
        assert!(JwtError::Invalid("Invalid issuer".into()).is_auth_failure());
        assert!(!JwtError::Network("x".into()).is_auth_failure());
    }

    #[test]
    fn display_and_user_message_contracts_are_locked() {
        assert_eq!(JwtError::storage("e").to_string(), "Storage error: e");
        assert_eq!(JwtError::config("e").to_string(), "Configuration error: e");
        assert_eq!(JwtError::network("e").to_string(), "Network error: e");
        assert_eq!(
            JwtError::invalid("Invalid issuer").to_string(),
            "Invalid issuer"
        );
        assert_eq!(
            JwtError::invalid("Invalid issuer").user_message(),
            "Invalid issuer"
        );
        assert_eq!(
            JwtError::network("e").user_message(),
            "Token authentication failed"
        );
    }
}
