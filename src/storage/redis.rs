// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! Redis blacklist driver (SETEX + EXISTS; lazy connection, reset on error).

use std::sync::Mutex;

use redis::Commands as _;

use super::sanitize_key_sha256;
use crate::error::JwtError;
use crate::storage::TokenStorage;

/// 建连与读写超时预算（对齐 memcached 驱动的 1s）：redis 同步连接默认无读超时，
/// 对端 SYN 黑洞/半开连接时会无限阻塞——持锁的 with_conn 会因此梗死整个驱动
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Redis 黑名单（SETEX + EXISTS；键：hex jti 原样 / 其他 sha256；懒连接、出错置空重建）
pub struct RedisTokenStorage {
    client: redis::Client,
    prefix: String,
    // ponytail: 单连接 + Mutex 串行化，高并发下换连接池（r2d2）
    conn: Mutex<Option<redis::Connection>>,
}

/// 手写 Debug（redis::Connection 非 Debug）：只列安全字段，下游组合时不泄连接内部
impl std::fmt::Debug for RedisTokenStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisTokenStorage")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl RedisTokenStorage {
    /// `addr` 支持 `host:port`（自动按 `redis://` 处理）或完整 `redis://` URL。
    /// `prefix` 为键前缀，原样拼接（调用方自带分隔符，如 "jwt_blacklist:"）。
    pub fn new(addr: Option<String>, prefix: String) -> Result<Self, JwtError> {
        let addr = addr.unwrap_or_else(|| "127.0.0.1:6379".into());
        let url = if addr.contains("://") {
            addr
        } else {
            format!("redis://{addr}")
        };
        let client = redis::Client::open(url)
            .map_err(|e| JwtError::storage(format!("Redis connection failed: {e}")))?;
        Ok(Self {
            client,
            prefix,
            conn: Mutex::new(None),
        })
    }

    /// 服务探测（测试与健康检查用；不触发 fail_open 路径）
    pub fn is_available(&self) -> bool {
        self.with_conn("ping", |c| redis::cmd("PING").query::<String>(c))
            .is_ok()
    }

    fn key(&self, jti: &str) -> String {
        format!("{}{}", self.prefix, sanitize_key_sha256(jti))
    }

    /// 闭包在持锁状态下执行：不得回调本类型的其他方法（非重入锁会死锁）。
    fn with_conn<T>(
        &self,
        op: &str,
        f: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
    ) -> Result<T, JwtError> {
        let mut guard = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // panic 期间连接状态未知：不 panic 恢复，但连接必须丢弃重建。
                // into_inner 不清中毒标志，必须 clear_poison，否则每次 lock() 都进本分支、连接每调用重建
                let mut g = poisoned.into_inner();
                *g = None;
                self.conn.clear_poison();
                g
            }
        };
        if guard.is_none() {
            let conn = self
                .client
                .get_connection_with_timeout(IO_TIMEOUT)
                .map_err(|e| JwtError::storage(format!("Redis connection failed: {e}")))?;
            conn.set_read_timeout(Some(IO_TIMEOUT))
                .map_err(|e| JwtError::storage(format!("Redis setup failed: {e}")))?;
            conn.set_write_timeout(Some(IO_TIMEOUT))
                .map_err(|e| JwtError::storage(format!("Redis setup failed: {e}")))?;
            *guard = Some(conn);
        }
        let result = f(guard.as_mut().expect("just ensured"));
        if result.is_err() {
            *guard = None; // 出错置空，下次调用重建连接
        }
        result.map_err(|e| JwtError::storage(format!("Redis {op} failed: {e}")))
    }
}

impl TokenStorage for RedisTokenStorage {
    fn blacklist(&self, jti: &str, expire_time: i64) -> Result<bool, JwtError> {
        let ttl = expire_time - crate::jwt::now();
        if ttl <= 0 {
            return Ok(true);
        }
        self.with_conn("blacklist", |c| c.set_ex(self.key(jti), "1", ttl as u64))
            .map(|()| true)
    }

    fn is_blacklisted(&self, jti: &str) -> Result<bool, JwtError> {
        let key = self.key(jti);
        self.with_conn("blacklist check", |c| c.exists(&key))
    }

    fn cleanup(&self) -> Result<bool, JwtError> {
        Ok(true) // Redis 自动过期
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::TokenStorage;

    fn storage() -> Option<RedisTokenStorage> {
        match RedisTokenStorage::new(Some("127.0.0.1:6379".into()), "jwt_rust_test:".into()) {
            Ok(s) => s.is_available().then_some(s),
            Err(_) => None,
        }
    }

    /// 服务不可达时显式失败：静默 skip 会给出假绿（CI 已配 service 容器，本地无服务请显式跳过）
    macro_rules! svc_or_skip {
        ($s:expr) => {
            match $s {
                Some(s) => s,
                None => {
                    if std::env::var_os("JWT_TEST_SKIP_SERVICES").is_some() {
                        eprintln!("skip: redis 不可用（JWT_TEST_SKIP_SERVICES 已设）");
                        return;
                    }
                    panic!(
                        "redis 127.0.0.1:6379 不可用：本测试需要真实服务（设 JWT_TEST_SKIP_SERVICES=1 跳过）"
                    );
                }
            }
        };
    }

    #[test]
    fn roundtrip_when_redis_available() {
        let s = svc_or_skip!(storage());
        let jti = format!("t{}", std::process::id());
        s.blacklist(&jti, now_secs() + 60).unwrap();
        assert!(s.is_blacklisted(&jti).unwrap());
        let ttl: i64 = s
            .with_conn("ttl", |c| redis::cmd("TTL").arg(s.key(&jti)).query(c))
            .unwrap();
        assert!((1..=60).contains(&ttl), "ttl={ttl}"); // SETEX 生效，非永久键
        assert!(s.cleanup().unwrap()); // 空实现
        let _ = s.with_conn("del", |c| {
            redis::cmd("DEL").arg(s.key(&jti)).query::<i64>(c)
        });
    }

    #[test]
    fn expired_ttl_is_noop() {
        let s = svc_or_skip!(storage());
        assert!(s.blacklist("x", 1).unwrap());
    }

    #[test]
    fn unreachable_server_is_storage_error_not_panic() {
        let s =
            RedisTokenStorage::new(Some("127.0.0.1:1".into()), "jwt_rust_test:".into()).unwrap();
        let t0 = std::time::Instant::now();
        assert!(!s.is_available());
        for _ in 0..2 {
            // 第二次证明可重试、不卡死
            let e = s.blacklist("x", now_secs() + 60).unwrap_err();
            assert!(matches!(e, JwtError::Storage(_)), "got {e:?}");
            assert!(e.to_string().contains("Redis connection failed"), "got {e}");
        }
        // 回归锁：建连/重建不得落到 OS 默认超时（分钟级）——1s 预算下 3 次建连远小于 5s
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            t0.elapsed()
        );
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}
