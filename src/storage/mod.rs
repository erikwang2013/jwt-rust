// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! Pluggable blacklist storage (file / redis / database / memcached).

use crate::error::JwtError;
use std::sync::Arc;

#[cfg(feature = "database")]
pub mod database;
pub mod file;
#[cfg(feature = "memcached")]
pub mod memcached;
#[cfg(feature = "redis")]
pub mod redis;
pub mod retry;

pub use file::FileTokenStorage;
pub use retry::RetryTokenStorage;

// ponytail: 同步存储调用，高并发下可 spawn_blocking 包装
/// 黑名单存储抽象（同步；对应 PHP TokenStorageInterface）
pub trait TokenStorage: Send + Sync {
    /// 将 jti 加入黑名单，expire_time 为 Unix 秒
    fn blacklist(&self, jti: &str, expire_time: i64) -> Result<bool, JwtError>;
    fn is_blacklisted(&self, jti: &str) -> Result<bool, JwtError>;
    fn cleanup(&self) -> Result<bool, JwtError>;
}

// Arc 委托：使 `RetryTokenStorage<Arc<dyn TokenStorage>>` 等组合满足 S: TokenStorage
impl<T: TokenStorage + ?Sized> TokenStorage for Arc<T> {
    fn blacklist(&self, jti: &str, expire_time: i64) -> Result<bool, JwtError> {
        (**self).blacklist(jti, expire_time)
    }
    fn is_blacklisted(&self, jti: &str) -> Result<bool, JwtError> {
        (**self).is_blacklisted(jti)
    }
    fn cleanup(&self) -> Result<bool, JwtError> {
        (**self).cleanup()
    }
}

/// 非十六进制 jti（如外部系统签发的 UUID）转 sha256 hex；
/// 本库签发的 hex jti 原样保留（对齐 PHP redis/memcached 驱动的键规则）
// 无 redis/memcached feature 时无生产调用方（仅测试引用）
#[allow(dead_code)]
pub(crate) fn sanitize_key_sha256(jti: &str) -> String {
    if !jti.is_empty() && jti.bytes().all(|b| b.is_ascii_hexdigit()) {
        return jti.to_string();
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(jti.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_jti_kept_as_is() {
        assert_eq!(sanitize_key_sha256("a1b2c3d4"), "a1b2c3d4");
    }

    #[test]
    fn non_hex_jti_hashed() {
        let key = sanitize_key_sha256("550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(key.len(), 64);
        assert_ne!(key, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn traversal_attempt_neutralized() {
        let key = sanitize_key_sha256("../../etc/passwd");
        assert_eq!(key.len(), 64); // 全部化 hex 摘要，无路径字符
    }

    #[test]
    fn empty_jti_is_hashed_like_php() {
        // PHP ctype_xdigit('') 为 false → sha256；空串 all() 恒真会把空 jti 变成裸前缀键，必须防住
        let key = sanitize_key_sha256("");
        assert_eq!(key.len(), 64);
        assert_eq!(
            key,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ); // sha256("")
    }

    #[test]
    fn arc_delegation_works() {
        let dir = std::env::temp_dir().join(format!("jwt_rust_test_arc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage: Arc<dyn TokenStorage> = Arc::new(
            FileTokenStorage::new(Some(dir))
                .unwrap()
                .with_gc_probability(0.0),
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(storage.blacklist("ab", now + 60).unwrap());
        assert!(storage.is_blacklisted("ab").unwrap());
        assert!(storage.cleanup().unwrap());
    }
}
