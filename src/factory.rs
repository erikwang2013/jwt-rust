// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! Factory assembling the JWT core with the configured storage (mirrors the PHP JWTFactory).

use std::path::Path;
use std::sync::Arc;

use crate::config::JwtConfig;
use crate::error::JwtError;
use crate::jwt::Jwt;
use crate::storage::{FileTokenStorage, RetryTokenStorage, TokenStorage};

/// 按配置组装内核与存储（对应 PHP JWTFactory）
pub struct JwtFactory;

impl JwtFactory {
    pub fn from_config(config: JwtConfig) -> Result<Jwt, JwtError> {
        let mut storage = Self::build_storage(&config)?;
        if config.advanced.retry_attempts > 1 {
            storage = Arc::new(RetryTokenStorage::new(
                storage,
                config.advanced.retry_attempts,
                config.advanced.retry_delay,
            ));
        }
        Jwt::new(config, storage)
    }

    pub fn from_env() -> Result<Jwt, JwtError> {
        Self::from_config(JwtConfig::from_env())
    }

    /// 从 TOML 配置文件组装内核（对应 PHP JWTFactory::createFromFile）
    pub fn from_file(path: &Path) -> Result<Jwt, JwtError> {
        Self::from_config(JwtConfig::from_toml_file(path)?)
    }

    fn build_storage(config: &JwtConfig) -> Result<Arc<dyn TokenStorage>, JwtError> {
        let s = &config.storage;
        match s.r#type.as_str() {
            "redis" => Self::redis(s),
            "database" => Self::database(s),
            "memcached" => Self::memcached(s),
            _ => {
                if s.r#type != "file" {
                    log::warn!(
                        "JWT storage: unknown type {:?}, falling back to file",
                        s.r#type
                    );
                }
                Self::file(s) // 未知类型回落 file（同 PHP 的 default 分支）
            }
        }
    }

    fn file(s: &crate::config::StorageConfig) -> Result<Arc<dyn TokenStorage>, JwtError> {
        let storage = FileTokenStorage::new(s.path.clone().map(std::path::PathBuf::from))?
            .with_gc_probability(s.gc_probability);
        Ok(Arc::new(storage))
    }

    #[cfg(feature = "redis")]
    fn redis(s: &crate::config::StorageConfig) -> Result<Arc<dyn TokenStorage>, JwtError> {
        Ok(Arc::new(crate::storage::redis::RedisTokenStorage::new(
            s.servers.first().cloned(),
            s.prefix.clone(),
        )?))
    }
    #[cfg(not(feature = "redis"))]
    fn redis(_: &crate::config::StorageConfig) -> Result<Arc<dyn TokenStorage>, JwtError> {
        Err(JwtError::config(
            "storage type redis requires the `redis` feature",
        ))
    }

    #[cfg(feature = "database")]
    fn database(s: &crate::config::StorageConfig) -> Result<Arc<dyn TokenStorage>, JwtError> {
        Ok(Arc::new(
            crate::storage::database::DatabaseTokenStorage::new(
                s.path.clone(),
                &s.table_name,
                s.auto_create_table,
            )?,
        ))
    }
    #[cfg(not(feature = "database"))]
    fn database(_: &crate::config::StorageConfig) -> Result<Arc<dyn TokenStorage>, JwtError> {
        Err(JwtError::config(
            "storage type database requires the `database` feature",
        ))
    }

    #[cfg(feature = "memcached")]
    fn memcached(s: &crate::config::StorageConfig) -> Result<Arc<dyn TokenStorage>, JwtError> {
        Ok(Arc::new(
            crate::storage::memcached::MemcachedTokenStorage::new(
                s.servers.clone(),
                s.prefix.clone(),
            )?,
        ))
    }
    #[cfg(not(feature = "memcached"))]
    fn memcached(_: &crate::config::StorageConfig) -> Result<Arc<dyn TokenStorage>, JwtError> {
        Err(JwtError::config(
            "storage type memcached requires the `memcached` feature",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JwtConfig;

    fn cfg(kind: &str) -> JwtConfig {
        JwtConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            storage: crate::config::StorageConfig {
                r#type: kind.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn file_driver_is_default_and_unknown_falls_back() {
        let j = JwtFactory::from_config(cfg("file")).unwrap();
        assert_eq!(j.algorithm(), "HS256");

        // 未知类型回落 file：只有 file 驱动会创建目录，据此证明分派落点（同 PHP default 分支）
        let dir =
            std::env::temp_dir().join(format!("jwt_rust_factory_unknown_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut c = cfg("nonsense");
        c.storage.path = Some(dir.to_string_lossy().into_owned());
        assert!(JwtFactory::from_config(c).is_ok());
        assert!(dir.is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn factory_wraps_retry_when_attempts_gt_one() {
        let dir =
            std::env::temp_dir().join(format!("jwt_rust_factory_retry_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_string_lossy().into_owned();

        let mut c = cfg("file");
        c.storage.path = Some(path.clone());
        c.advanced = crate::config::AdvancedConfig {
            retry_attempts: 3,
            retry_delay: 1,
            ..Default::default()
        };
        let j = JwtFactory::from_config(c).unwrap();
        let token = j
            .encode(&serde_json::json!({"user_id": 1}), Some(60))
            .unwrap();
        let jti = j.payload_without_validation(&token).unwrap()["jti"]
            .as_str()
            .unwrap()
            .to_string();
        std::fs::create_dir_all(dir.join(format!("{jti}.json"))).unwrap();
        let e = j.blacklist(&token).unwrap_err();
        assert!(e.to_string().contains("after 3 attempts"), "got: {e}");

        let mut c1 = cfg("file");
        c1.storage.path = Some(path);
        c1.advanced = crate::config::AdvancedConfig {
            retry_attempts: 1,
            retry_delay: 1,
            ..Default::default()
        };
        let j1 = JwtFactory::from_config(c1).unwrap();
        let token1 = j1
            .encode(&serde_json::json!({"user_id": 1}), Some(60))
            .unwrap();
        let jti1 = j1.payload_without_validation(&token1).unwrap()["jti"]
            .as_str()
            .unwrap()
            .to_string();
        std::fs::create_dir_all(dir.join(format!("{jti1}.json"))).unwrap();
        let e1 = j1.blacklist(&token1).unwrap_err();
        assert!(!e1.to_string().contains("attempts"), "got: {e1}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(feature = "redis"))]
    #[test]
    fn redis_without_feature_is_config_error() {
        // let-else 而非 unwrap_err()：Jwt 持有密钥材料，不为其实现 Debug（unwrap_err 的 T: Debug 约束）
        let Err(e) = JwtFactory::from_config(cfg("redis")) else {
            panic!("redis without the feature must be a config error");
        };
        assert!(matches!(e, JwtError::Config(_)));
        assert!(e.to_string().contains("feature"));
    }

    #[test]
    fn from_file_smoke() {
        let dir = std::env::temp_dir().join(format!("jwt_rust_factory_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("jwt.toml");
        std::fs::write(&p, "secret_key = \"0123456789abcdef0123456789abcdef\"\n").unwrap();
        assert!(JwtFactory::from_file(&p).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
