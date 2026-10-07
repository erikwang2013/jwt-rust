// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! Storage retry decorator (mirrors the PHP RetryTokenStorage).

use std::time::Duration;

use super::TokenStorage;
use crate::error::JwtError;

/// 存储操作失败自动重试（对应 PHP RetryTokenStorage）；
/// Config 错误不重试，重试耗尽抛 Storage 错误并带操作名
pub struct RetryTokenStorage<S: TokenStorage> {
    inner: S,
    max_retries: u32,
    retry_delay_ms: u64,
}

impl<S: TokenStorage> RetryTokenStorage<S> {
    /// Wrap `inner` with fixed-delay retries.
    ///
    /// `max_retries` is the total number of attempts (matching the PHP
    /// `$maxRetries` loop), not additional retries; values below 1 are
    /// clamped to 1. `retry_delay_ms` is the fixed delay between attempts.
    pub fn new(inner: S, max_retries: u32, retry_delay_ms: u64) -> Self {
        Self {
            inner,
            max_retries,
            retry_delay_ms,
        }
    }

    /// Borrow the wrapped storage (e.g. for tests/inspection).
    pub fn inner(&self) -> &S {
        &self.inner
    }

    // ponytail: 阻塞 sleep（最坏 delay×(attempts-1)，默认 2×100ms）；异步适配层应在 spawn_blocking 内调用存储操作
    fn retry<T>(
        &self,
        op: &str,
        mut f: impl FnMut() -> Result<T, JwtError>,
    ) -> Result<T, JwtError> {
        let attempts = self.max_retries.max(1);
        let mut last: Option<JwtError> = None;
        for attempt in 1..=attempts {
            match f() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    // Config 错误立即放弃重试（对齐 PHP CONFIG_ERROR 分支）
                    if matches!(e, JwtError::Config(_)) || attempt == attempts {
                        last = Some(e);
                        break;
                    }
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(self.retry_delay_ms));
                }
            }
        }
        let detail = last.map(|e| e.to_string()).unwrap_or_default();
        Err(JwtError::storage(format!(
            "Operation {op} failed after {attempts} attempts: {detail}"
        )))
    }
}

impl<S: TokenStorage> TokenStorage for RetryTokenStorage<S> {
    fn blacklist(&self, jti: &str, expire_time: i64) -> Result<bool, JwtError> {
        self.retry("blacklist", || self.inner.blacklist(jti, expire_time))
    }
    fn is_blacklisted(&self, jti: &str) -> Result<bool, JwtError> {
        self.retry("isBlacklisted", || self.inner.is_blacklisted(jti))
    }
    fn cleanup(&self) -> Result<bool, JwtError> {
        self.retry("cleanup", || self.inner.cleanup())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::JwtError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FailN {
        fail_times: usize,
        calls: AtomicUsize,
        err: JwtError,
    }
    impl TokenStorage for FailN {
        fn blacklist(&self, _j: &str, _e: i64) -> Result<bool, JwtError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                Err(self.err.clone())
            } else {
                Ok(true)
            }
        }
        fn is_blacklisted(&self, _j: &str) -> Result<bool, JwtError> {
            Ok(false)
        }
        fn cleanup(&self) -> Result<bool, JwtError> {
            Ok(true)
        }
    }

    #[test]
    fn retries_until_success() {
        let inner = FailN {
            fail_times: 2,
            calls: AtomicUsize::new(0),
            err: JwtError::Storage("boom".into()),
        };
        let s = RetryTokenStorage::new(inner, 3, 1);
        assert!(s.blacklist("j", 9999999999).unwrap());
    }

    #[test]
    fn exhausts_and_reports() {
        let inner = FailN {
            fail_times: 10,
            calls: AtomicUsize::new(0),
            err: JwtError::Storage("boom".into()),
        };
        let s = RetryTokenStorage::new(inner, 2, 1);
        let e = s.blacklist("j", 9999999999).unwrap_err();
        assert!(matches!(e, JwtError::Storage(_)));
        assert!(e.to_string().contains("after 2 attempts"));
    }

    #[test]
    fn config_error_not_retried() {
        let inner = FailN {
            fail_times: 10,
            calls: AtomicUsize::new(0),
            err: JwtError::Config("bad".into()),
        };
        let s = RetryTokenStorage::new(inner, 3, 1);
        let _ = s.blacklist("j", 9999999999);
        assert_eq!(inner_calls(&s), 1); // 只尝试一次
    }

    #[test]
    fn zero_max_retries_clamps_to_one_attempt() {
        let inner = FailN {
            fail_times: 10,
            calls: AtomicUsize::new(0),
            err: JwtError::Storage("boom".into()),
        };
        let s = RetryTokenStorage::new(inner, 0, 1);
        let e = s.blacklist("j", 9999999999).unwrap_err();
        assert!(e.to_string().contains("after 1 attempts"));
        assert_eq!(inner_calls(&s), 1);
    }

    fn inner_calls(s: &RetryTokenStorage<FailN>) -> usize {
        s.inner().calls.load(Ordering::SeqCst)
    }
}
