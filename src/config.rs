// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
// jwt-rust - JWT authentication for Rust web frameworks
//! Configuration.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::JwtError;

// 不派生 Debug，改为手写实现：secret_key 是密钥材料，{:?} 进日志/panic 消息不得泄露
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JwtConfig {
    pub secret_key: String,
    pub algorithm: String,
    pub issuer: String,
    pub audience: String,
    pub leeway: u64,
    pub default_expire: u64,
    pub refresh_expire: u64,
    pub storage: StorageConfig,
    pub advanced: AdvancedConfig,
    pub middleware: MiddlewareConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub r#type: String,
    pub prefix: String,
    pub path: Option<String>,
    pub table_name: String,
    pub auto_create_table: bool,
    pub gc_probability: f64,
    pub fail_open: bool,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdvancedConfig {
    pub retry_attempts: u32,
    pub retry_delay: u64,      // 毫秒
    pub auto_cleanup: bool,    // Rust 版不自动执行：保留供背景任务读取
    pub cleanup_interval: u64, // 秒
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MiddlewareConfig {
    pub except: Vec<String>,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret_key: String::new(),
            algorithm: "HS256".into(),
            issuer: String::new(),
            audience: String::new(),
            leeway: 0,
            default_expire: 3600,
            refresh_expire: 7200,
            storage: StorageConfig::default(),
            advanced: AdvancedConfig::default(),
            middleware: MiddlewareConfig::default(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            r#type: "file".into(),
            prefix: "jwt_blacklist:".into(),
            path: None,
            table_name: "jwt_blacklist".into(),
            auto_create_table: true,
            gc_probability: 0.1,
            fail_open: false,
            // 空列表 = 各驱动按自身默认回落（redis → 127.0.0.1:6379、memcached → 127.0.0.1:11211）。
            // 不要写死端口默认值：固定 11211 会让未配 servers 的 redis 驱动错连
            servers: vec![],
        }
    }
}

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("secret_key", &"[redacted]")
            .field("algorithm", &self.algorithm)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("leeway", &self.leeway)
            .field("default_expire", &self.default_expire)
            .field("refresh_expire", &self.refresh_expire)
            .field("storage", &self.storage)
            .field("advanced", &self.advanced)
            .field("middleware", &self.middleware)
            .finish()
    }
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            retry_attempts: 3,
            retry_delay: 100,
            auto_cleanup: false,
            cleanup_interval: 3600,
        }
    }
}

impl JwtConfig {
    /// Load configuration from process environment variables (`JWT_*` names).
    pub fn from_env() -> Self {
        Self::from_map(std::env::vars())
    }

    /// Testable core: any key-value pairs. Invalid numbers fall back to defaults.
    pub fn from_map<I: IntoIterator<Item = (String, String)>>(vars: I) -> Self {
        let mut c = Self::default();
        for (k, v) in vars {
            match k.as_str() {
                "JWT_SECRET_KEY" => c.secret_key = v,
                "JWT_ALGORITHM" => c.algorithm = v,
                "JWT_ISSUER" => c.issuer = v,
                "JWT_AUDIENCE" => c.audience = v,
                "JWT_LEEWAY" => c.leeway = v.parse().unwrap_or(c.leeway),
                "JWT_DEFAULT_EXPIRE" => c.default_expire = v.parse().unwrap_or(c.default_expire),
                "JWT_REFRESH_EXPIRE" => c.refresh_expire = v.parse().unwrap_or(c.refresh_expire),
                "JWT_STORAGE_TYPE" => c.storage.r#type = v,
                "JWT_STORAGE_PREFIX" => c.storage.prefix = v,
                "JWT_STORAGE_PATH" => c.storage.path = if v.is_empty() { None } else { Some(v) },
                "JWT_STORAGE_TABLE" => c.storage.table_name = v,
                "JWT_STORAGE_AUTO_CREATE_TABLE" => c.storage.auto_create_table = truthy(&v),
                "JWT_STORAGE_GC_PROBABILITY" => {
                    c.storage.gc_probability = v.parse().unwrap_or(c.storage.gc_probability)
                }
                "JWT_STORAGE_FAIL_OPEN" => c.storage.fail_open = truthy(&v),
                "JWT_ADVANCED_RETRY_ATTEMPTS" => {
                    c.advanced.retry_attempts = v.parse().unwrap_or(c.advanced.retry_attempts)
                }
                "JWT_ADVANCED_RETRY_DELAY" => {
                    c.advanced.retry_delay = v.parse().unwrap_or(c.advanced.retry_delay)
                }
                "JWT_AUTO_CLEANUP" => c.advanced.auto_cleanup = truthy(&v),
                "JWT_CLEANUP_INTERVAL" => {
                    c.advanced.cleanup_interval = v.parse().unwrap_or(c.advanced.cleanup_interval)
                }
                _ => {}
            }
        }
        c
    }

    /// Load configuration from a TOML file (keys are this struct's fields).
    /// Unknown keys are ignored (lenient parsing).
    pub fn from_toml_file(path: &Path) -> Result<Self, JwtError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            JwtError::config(format!("Cannot read config file: {} ({e})", path.display()))
        })?;
        toml::from_str(&text).map_err(|e| JwtError::config(format!("Invalid config file: {e}")))
    }

    pub fn with_secret(mut self, secret: impl Into<String>) -> Self {
        self.secret_key = secret.into();
        self
    }
    pub fn with_issuer(mut self, iss: impl Into<String>) -> Self {
        self.issuer = iss.into();
        self
    }
    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.audience = aud.into();
        self
    }
    pub fn with_storage_type(mut self, t: impl Into<String>) -> Self {
        self.storage.r#type = t.into();
        self
    }
    pub fn with_except(mut self, patterns: Vec<String>) -> Self {
        self.middleware.except = patterns;
        self
    }
}

/// 宽松布尔解析：1 / true / yes / on（trim 后、大小写不敏感）为真，其余为假。
fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn defaults_match_config_template() {
        let c = JwtConfig::from_map(map(&[]));
        assert_eq!(c.algorithm, "HS256");
        assert_eq!(c.leeway, 0);
        assert_eq!(c.default_expire, 3600);
        assert_eq!(c.refresh_expire, 7200);
        assert_eq!(c.storage.r#type, "file");
        assert_eq!(c.storage.prefix, "jwt_blacklist:");
        assert_eq!(c.storage.table_name, "jwt_blacklist");
        assert!(c.storage.auto_create_table);
        assert_eq!(c.storage.gc_probability, 0.1);
        assert!(!c.storage.fail_open);
        assert!(c.storage.servers.is_empty()); // 空 = 各驱动自回落（不写死端口）
        assert_eq!(c.advanced.retry_attempts, 3);
        assert_eq!(c.advanced.retry_delay, 100);
        assert!(!c.advanced.auto_cleanup);
        assert_eq!(c.advanced.cleanup_interval, 3600);
        assert!(c.middleware.except.is_empty());
        assert_eq!(c.secret_key, "");
        assert_eq!(c.issuer, "");
        assert_eq!(c.audience, "");
        assert_eq!(c.storage.path, None);
    }

    #[test]
    fn debug_redacts_secret_key() {
        let c = JwtConfig::default().with_secret("super-secret-value-that-must-not-leak");
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("super-secret-value"), "secret leaked: {dbg}");
        assert!(dbg.contains("[redacted]"));
        assert!(dbg.contains("algorithm")); // 其余字段照常可见
    }

    #[test]
    fn env_names_are_stable() {
        let c = JwtConfig::from_map(map(&[
            ("JWT_SECRET_KEY", "s"),
            ("JWT_ALGORITHM", "HS512"),
            ("JWT_ISSUER", "iss"),
            ("JWT_AUDIENCE", "aud"),
            ("JWT_LEEWAY", "30"),
            ("JWT_DEFAULT_EXPIRE", "60"),
            ("JWT_REFRESH_EXPIRE", "120"),
            ("JWT_STORAGE_TYPE", "redis"),
            ("JWT_STORAGE_PREFIX", "p:"),
            ("JWT_STORAGE_PATH", "/tmp/x"),
            ("JWT_STORAGE_TABLE", "t"),
            ("JWT_STORAGE_AUTO_CREATE_TABLE", "0"),
            ("JWT_STORAGE_GC_PROBABILITY", "0.5"),
            ("JWT_STORAGE_FAIL_OPEN", "1"),
            ("JWT_ADVANCED_RETRY_ATTEMPTS", "5"),
            ("JWT_ADVANCED_RETRY_DELAY", "10"),
            ("JWT_AUTO_CLEANUP", "1"),
            ("JWT_CLEANUP_INTERVAL", "60"),
        ]));
        assert_eq!(c.algorithm, "HS512");
        assert_eq!(c.leeway, 30);
        assert_eq!(c.default_expire, 60);
        assert_eq!(c.storage.r#type, "redis");
        assert_eq!(c.storage.path.as_deref(), Some("/tmp/x"));
        assert!(!c.storage.auto_create_table);
        assert_eq!(c.storage.gc_probability, 0.5);
        assert!(c.storage.fail_open);
        assert_eq!(c.advanced.retry_attempts, 5);
        assert!(c.advanced.auto_cleanup);
        assert_eq!(c.secret_key, "s");
        assert_eq!(c.issuer, "iss");
        assert_eq!(c.audience, "aud");
        assert_eq!(c.refresh_expire, 120);
        assert_eq!(c.storage.prefix, "p:");
        assert_eq!(c.storage.table_name, "t");
        assert_eq!(c.advanced.retry_delay, 10);
        assert_eq!(c.advanced.cleanup_interval, 60);
    }

    #[test]
    fn truthy_matches_filter_validate_boolean() {
        for t in ["1", "true", "TRUE", "on", "Yes", " on "] {
            assert!(truthy(t));
        }
        for f in ["0", "false", "no", "off", "", "garbage"] {
            assert!(!truthy(f));
        }
    }

    #[test]
    fn bad_numbers_fall_back_to_defaults() {
        let c = JwtConfig::from_map(map(&[
            ("JWT_LEEWAY", "abc"),
            ("JWT_STORAGE_GC_PROBABILITY", "x"),
        ]));
        assert_eq!(c.leeway, 0);
        assert_eq!(c.storage.gc_probability, 0.1);
    }

    #[test]
    fn toml_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("jwt_rust_cfg_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jwt.toml");
        std::fs::write(
            &path,
            r#"
secret_key = "0123456789abcdef0123456789abcdef"
algorithm = "HS256"
bogus_key = "x"
[storage]
type = "file"
fail_open = true
"#,
        )
        .unwrap();
        let c = JwtConfig::from_toml_file(&path).unwrap();
        assert!(c.storage.fail_open);
        assert_eq!(c.secret_key.len(), 32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_toml_file_error_branches() {
        let missing = std::path::Path::new("/nonexistent/jwt_rust_nope.toml");
        let e = JwtConfig::from_toml_file(missing).unwrap_err();
        assert!(matches!(e, JwtError::Config(_)));
        assert_eq!(e.code(), 5);

        let dir = std::env::temp_dir().join(format!("jwt_rust_cfg_bad_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.toml");
        std::fs::write(&bad, "[storage").unwrap();
        assert!(matches!(
            JwtConfig::from_toml_file(&bad).unwrap_err(),
            JwtError::Config(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
