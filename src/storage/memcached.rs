// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! Memcached blacklist driver (set + get; >30d TTL absolute-timestamp quirk preserved).

use std::sync::{Mutex, MutexGuard};

use super::{TokenStorage, sanitize_key_sha256};
use crate::error::JwtError;

/// Memcached 黑名单（set + 读；>30 天 TTL 按绝对时间戳的协议坑照搬修复）
pub struct MemcachedTokenStorage {
    urls: Vec<String>,
    // ponytail: Mutex 串行化（Client 内置 r2d2 默认每服务器 max_size=1）；要吞吐时调池大小并去掉锁
    client: Mutex<Option<memcache::Client>>,
    prefix: String,
}

impl MemcachedTokenStorage {
    /// `servers` 支持 `host:port`（自动按 `memcache://host:port` 处理）或完整 `memcache://` URL；
    /// 空列表回落 `127.0.0.1:11211`（对齐 config 默认）。`prefix` 原样拼接（调用方自带分隔符）。
    /// 构造不建连（惰性，对齐 PHP addServer）；连接/操作错误在首次使用时以 Storage 错误上抛，由 fail_open 策略处置。
    pub fn new(servers: Vec<String>, prefix: String) -> Result<Self, JwtError> {
        let servers = if servers.is_empty() {
            vec!["127.0.0.1:11211".to_string()]
        } else {
            servers
        };
        let urls: Vec<String> = servers
            .into_iter()
            .map(|s| {
                if s.contains("://") {
                    s
                } else {
                    format!("memcache://{s}")
                }
            })
            .collect();
        Ok(Self {
            urls,
            client: Mutex::new(None),
            prefix,
        })
    }

    /// 探测是否全部服务器可达（任一不可达即 false）。
    pub fn is_available(&self) -> bool {
        self.with_client("version", |c| c.version().map(|_| ()))
            .is_ok()
    }

    fn key(&self, jti: &str) -> String {
        format!("{}{}", self.prefix, sanitize_key_sha256(jti))
    }

    /// 惰性建连 + 持锁执行闭包（同 redis 家族：出错置空、下次调用重建）。
    /// 闭包在持锁状态下执行：不得回调本类型的其他方法（非重入锁会死锁）。
    /// 建连失败为 `Memcached connection failed`；操作失败为 `Memcached {op} failed`。
    fn with_client<T>(
        &self,
        op: &str,
        f: impl FnOnce(&memcache::Client) -> Result<T, memcache::MemcacheError>,
    ) -> Result<T, JwtError> {
        let mut guard = self.lock();
        if guard.is_none() {
            // 对齐 PHP OPT_CONNECT_TIMEOUT 默认 1000ms（r2d2 默认 30s 会让宕机时每次操作挂 30s）
            let client = memcache::Client::builder()
                .add_server(self.urls.clone())
                .and_then(|b| {
                    b.with_connection_timeout(std::time::Duration::from_secs(1))
                        .build()
                })
                .map_err(|e| JwtError::storage(format!("Memcached connection failed: {e}")))?;
            *guard = Some(client);
        }
        let result = f(guard.as_ref().expect("just ensured"));
        if result.is_err() {
            *guard = None; // 出错置空，下次重建（对应 PHP 的连接断开重连 / redis 家族同款）
        }
        result.map_err(|e| JwtError::storage(format!("Memcached {op} failed: {e}")))
    }

    /// 取客户端锁；中毒时按 database.rs 先例 clear_poison + 复用连接池：
    /// 坏连接在 checkin/checkout 时经 is_valid 丢弃，可安全复用；
    /// 不 clear_poison 则中毒标志永久残留、每次 lock() 都走 Err 分支。
    fn lock(&self) -> MutexGuard<'_, Option<memcache::Client>> {
        match self.client.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                self.client.clear_poison();
                poisoned.into_inner()
            }
        }
    }
}

impl TokenStorage for MemcachedTokenStorage {
    fn blacklist(&self, jti: &str, expire_time: i64) -> Result<bool, JwtError> {
        let now = crate::jwt::now();
        let mut ttl = expire_time - now;
        if ttl <= 0 {
            return Ok(true);
        }
        // Memcached 协议：>2592000(30 天) 的 TTL 被当作绝对 Unix 时间戳
        if ttl > 2_592_000 {
            ttl += now;
        }
        // 钳到 u32::MAX：极端 ttl（2106 年后）直接 `as u32` 会回绕成过去时间而立即过期
        let ttl = ttl.min(u32::MAX as i64) as u32;
        self.with_client("blacklist", |c| c.set(&self.key(jti), "1", ttl))
            .map(|()| true) // memcache 对 set 的 NOT_STORED 不适用（为 add/replace 保留），Err 已走 with_client 的 map_err
    }

    fn is_blacklisted(&self, jti: &str) -> Result<bool, JwtError> {
        // Ok(None) 即 PHP 的 RES_NOTFOUND → false；其余错误必须冒泡（静默 false 会放行本应拦截的令牌）
        match self.with_client("blacklist check", |c| c.get::<String>(&self.key(jti)))? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    fn cleanup(&self) -> Result<bool, JwtError> {
        Ok(true) // Memcached 自动过期（对齐 PHP 空实现）
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::TokenStorage;

    fn storage() -> Option<MemcachedTokenStorage> {
        match MemcachedTokenStorage::new(vec!["127.0.0.1:11211".into()], "jwt_rust_test:".into()) {
            Ok(s) => s.is_available().then_some(s),
            Err(_) => None,
        }
    }

    #[test]
    fn roundtrip_when_available() {
        let Some(s) = storage() else {
            eprintln!("skip: memcached 不可用");
            return;
        };
        let jti = format!("m{}", std::process::id());
        assert!(s.blacklist(&jti, crate::jwt::now() + 60).unwrap());
        assert!(s.is_blacklisted(&jti).unwrap());
        assert!(!s.is_blacklisted("definitely-absent-key").unwrap());
        assert!(s.cleanup().unwrap());
    }

    /// >30 天 TTL 必须按绝对时间戳写入（否则 memcached 当作 1970 年的时间点、立即过期）
    #[test]
    fn far_future_expiry_uses_absolute_timestamp() {
        let Some(s) = storage() else {
            eprintln!("skip: memcached 不可用");
            return;
        };
        let jti = format!("m{}d", std::process::id());
        assert!(s.blacklist(&jti, crate::jwt::now() + 60 * 86400).unwrap());
        assert!(s.is_blacklisted(&jti).unwrap());
        // 清理自己的键（trait 无 delete 语义）：不留一个 60 天 TTL 的测试条目在缓存里
        if let Some(c) = s.client.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = c.delete(&s.key(&jti));
        }
        assert!(!s.is_blacklisted(&jti).unwrap());
    }

    #[test]
    fn expired_and_empty_inputs() {
        let Some(s) = storage() else {
            eprintln!("skip: memcached 不可用");
            return;
        };
        assert!(s.blacklist("x", 1).unwrap()); // 已过期 → no-op
        assert!(!s.is_blacklisted("").unwrap()); // 空 jti → sha256("") 键，不存在
    }

    /// 回归锁：惰性构造必须成功，首个操作才报 Storage 错误，且连接超时为 1s 级而非 r2d2 默认 30s
    #[test]
    fn unreachable_server_fails_fast_at_first_op() {
        let s = MemcachedTokenStorage::new(vec!["127.0.0.1:1".into()], "jwt_rust_test:".into())
            .unwrap();
        let t0 = std::time::Instant::now();
        assert!(!s.is_available());
        assert!(matches!(
            s.blacklist("x", crate::jwt::now() + 60),
            Err(JwtError::Storage(_))
        ));
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            t0.elapsed()
        );
    }
}
