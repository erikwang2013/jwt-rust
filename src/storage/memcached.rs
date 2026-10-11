// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! Memcached blacklist driver: per-server pools with deterministic key routing
//! (a single dead server no longer disables the driver; >30d TTL absolute-timestamp quirk preserved).

use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::Duration;

use super::{TokenStorage, sanitize_key_sha256};
use crate::error::JwtError;

/// 连接池预算（1000ms；r2d2 默认 30s 会让宕机时每次操作挂 30s）。
/// 注意：该预算约束的是池的取得/初始化等待，socket 读写超时未设置（memcache 0.21 需 URL `?timeout=` 才设）
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// 每服务器池大小（r2d2 默认 1；配合读锁并发，>1 才有实际并行度）
const POOL_SIZE: u32 = 4;

/// Memcached 黑名单：每服务器独立连接池（惰性构建），按 key 做确定性哈希路由。
///
/// 单台不可达只在构建时告警剔除该池（其余服务器照常服务，下轮调用再尝试重建），
/// 全部不可达才报 Storage——健康节点继续服务的降级语义。
/// 旧实现把所有服务器塞进单个 Client：任一建连失败即整体构建失败，一台宕机拖垮整个驱动。
///
/// 并发：读路径持读锁执行（多请求可并行命中各自连接池），仅构建/剔除服务器时取写锁。
pub struct MemcachedTokenStorage {
    urls: Vec<String>,
    clients: RwLock<Vec<Arc<memcache::Client>>>,
    prefix: String,
}

/// 手写 Debug（memcache::Client 非 Debug）：只列安全字段，下游组合时不泄连接内部
impl std::fmt::Debug for MemcachedTokenStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemcachedTokenStorage")
            .field("urls", &self.urls)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl MemcachedTokenStorage {
    /// `servers` 支持 `host:port`（自动按 `memcache://host:port` 处理）或完整 `memcache://` URL；
    /// 空列表回落 `127.0.0.1:11211`（对齐 config 默认）。`prefix` 原样拼接（调用方自带分隔符）。
    /// 构造不建连（惰性建连）；连接/操作错误在首次使用时以 Storage 错误上抛，由 fail_open 策略处置。
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
            clients: RwLock::new(Vec::new()),
            prefix,
        })
    }

    /// 探测是否至少一台服务器可达（构建 + version 探活）。
    pub fn is_available(&self) -> bool {
        self.ensure_clients();
        self.read().iter().any(|c| c.version().is_ok())
    }

    fn key(&self, jti: &str) -> String {
        format!("{}{}", self.prefix, sanitize_key_sha256(jti))
    }

    /// 惰性建连：逐服务器构建，失败者仅告警剔除（一台宕机不再连坐其余服务器）。
    /// 双检锁：并发首用时只构建一次。
    fn ensure_clients(&self) {
        if !self.read().is_empty() {
            return;
        }
        let mut guard = self.write();
        if !guard.is_empty() {
            return;
        }
        for url in &self.urls {
            match Self::build_client(url) {
                Ok(c) => guard.push(Arc::new(c)),
                Err(e) => log::warn!("JWT memcached: server {url} unavailable, skipping: {e}"),
            }
        }
    }

    fn build_client(url: &str) -> Result<memcache::Client, memcache::MemcacheError> {
        memcache::Client::builder()
            .add_server(vec![url.to_string()])
            .and_then(|b| {
                b.with_max_pool_size(POOL_SIZE)
                    .with_connection_timeout(CONNECT_TIMEOUT)
                    .build()
            })
    }

    /// 读路径：持读锁执行闭包（多请求可并行；闭包不得回调本类型的其他方法，非重入锁会死锁）。
    /// 操作失败即剔除当轮对应服务器（下轮按剩余集合重建/路由），错误以 Storage 上抛。
    fn with_key<T>(
        &self,
        op: &str,
        key: &str,
        f: impl FnOnce(&memcache::Client) -> Result<T, memcache::MemcacheError>,
    ) -> Result<T, JwtError> {
        self.ensure_clients();
        let (result, idx) = {
            let guard = self.read();
            if guard.is_empty() {
                return Err(JwtError::storage(format!(
                    "Memcached connection failed: none of the {} configured server(s) is reachable",
                    self.urls.len()
                )));
            }
            let idx = route_index(key, guard.len());
            (f(&guard[idx]), idx)
        };
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                log::warn!("JWT memcached: dropping one server after {op} error: {e}");
                self.drop_server(idx);
                Err(JwtError::storage(format!("Memcached {op} failed: {e}")))
            }
        }
    }

    /// 剔除失败服务器（写锁；索引越界视为已被并发的同类错误剔除）。
    fn drop_server(&self, idx: usize) {
        let mut guard = self.write();
        if idx < guard.len() {
            guard.remove(idx);
        }
    }

    /// 取读锁；中毒时按 database.rs 先例 clear_poison + 复用连接池：
    /// 坏连接在 checkin/checkout 时经 is_valid 丢弃，可安全复用；
    /// 不 clear_poison 则中毒标志永久残留、每次加锁都走 Err 分支。
    fn read(&self) -> RwLockReadGuard<'_, Vec<Arc<memcache::Client>>> {
        match self.clients.read() {
            Ok(g) => g,
            Err(poisoned) => {
                self.clients.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Vec<Arc<memcache::Client>>> {
        match self.clients.write() {
            Ok(g) => g,
            Err(poisoned) => {
                self.clients.clear_poison();
                poisoned.into_inner()
            }
        }
    }
}

/// 跨进程稳定的确定性路由（FNV-1a 64）：同一 key 无论重启/何时都落同一服务器，
/// 黑名单「写哪台读哪台」保持一致；std 的 RandomState 每进程随机，不能用。
fn route_index(key: &str, n: usize) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h % n as u64) as usize
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
        let key = self.key(jti);
        self.with_key("blacklist", &key, |c| c.set(&key, "1", ttl))
            .map(|()| true) // memcache 对 set 的 NOT_STORED 不适用（为 add/replace 保留），Err 已走 with_key 的 map_err
    }

    fn is_blacklisted(&self, jti: &str) -> Result<bool, JwtError> {
        // Ok(None)（键不存在）→ false；其余错误必须冒泡（静默 false 会放行本应拦截的令牌）
        let key = self.key(jti);
        match self.with_key("blacklist check", &key, |c| c.get::<String>(&key))? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    fn cleanup(&self) -> Result<bool, JwtError> {
        Ok(true) // Memcached 自动过期，无需主动清理
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

    /// 服务不可达时显式失败：静默 skip 会给出假绿（CI 已配 service 容器，本地无服务请显式跳过）
    macro_rules! svc_or_skip {
        ($s:expr) => {
            match $s {
                Some(s) => s,
                None => {
                    if std::env::var_os("JWT_TEST_SKIP_SERVICES").is_some() {
                        eprintln!("skip: memcached 不可用（JWT_TEST_SKIP_SERVICES 已设）");
                        return;
                    }
                    panic!(
                        "memcached 127.0.0.1:11211 不可用：本测试需要真实服务（设 JWT_TEST_SKIP_SERVICES=1 跳过）"
                    );
                }
            }
        };
    }

    /// 清理测试键（trait 无 delete 语义）：按路由落点删除
    fn del(s: &MemcachedTokenStorage, jti: &str) {
        let key = s.key(jti);
        let guard = s.read();
        if let Some(c) = guard.get(route_index(&key, guard.len().max(1))) {
            let _ = c.delete(&key);
        }
    }

    #[test]
    fn roundtrip_when_available() {
        let s = svc_or_skip!(storage());
        let jti = format!("m{}", std::process::id());
        assert!(s.blacklist(&jti, crate::jwt::now() + 60).unwrap());
        assert!(s.is_blacklisted(&jti).unwrap());
        assert!(!s.is_blacklisted("definitely-absent-key").unwrap());
        assert!(s.cleanup().unwrap());
        del(&s, &jti);
    }

    /// >30 天 TTL 必须按绝对时间戳写入（否则 memcached 当作 1970 年的时间点、立即过期）
    #[test]
    fn far_future_expiry_uses_absolute_timestamp() {
        let s = svc_or_skip!(storage());
        let jti = format!("m{}d", std::process::id());
        assert!(s.blacklist(&jti, crate::jwt::now() + 60 * 86400).unwrap());
        assert!(s.is_blacklisted(&jti).unwrap());
        del(&s, &jti);
        assert!(!s.is_blacklisted(&jti).unwrap());
    }

    #[test]
    fn expired_and_empty_inputs() {
        let s = svc_or_skip!(storage());
        assert!(s.blacklist("x", 1).unwrap()); // 已过期 → no-op
        assert!(!s.is_blacklisted("").unwrap()); // 空 jti → sha256("") 键，不存在
    }

    /// 回归锁：一台服务器宕机不得拖垮整个驱动——健康服务器继续服务（旧实现为全有或全无）
    #[test]
    fn dead_server_does_not_disable_driver() {
        // 探活为 true 即证明 11211 健康节点在 1 号端口不可达时仍被保留
        let s = svc_or_skip!(
            Some(
                MemcachedTokenStorage::new(
                    vec!["127.0.0.1:11211".into(), "127.0.0.1:1".into()],
                    "jwt_rust_test:".into(),
                )
                .unwrap()
            )
            .filter(|s| s.is_available())
        );
        let jti = format!("md{}", std::process::id());
        assert!(s.blacklist(&jti, crate::jwt::now() + 60).unwrap());
        assert!(s.is_blacklisted(&jti).unwrap());
        del(&s, &jti);
    }

    /// 回归锁：惰性构造必须成功，首个操作才报 Storage 错误，且连接超时为 1s 级而非 r2d2 默认 30s
    #[test]
    fn unreachable_server_fails_fast_at_first_op() {
        let s = MemcachedTokenStorage::new(vec!["127.0.0.1:1".into()], "jwt_rust_test:".into())
            .unwrap();
        let t0 = std::time::Instant::now();
        assert!(!s.is_available());
        let e = s.blacklist("x", crate::jwt::now() + 60).unwrap_err();
        assert!(matches!(e, JwtError::Storage(_)), "got {e:?}");
        assert!(e.to_string().contains("none of the"), "got {e}");
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            t0.elapsed()
        );
    }
}
