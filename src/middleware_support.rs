// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
// jwt-rust - JWT authentication for Rust web frameworks
//! Shared except-whitelist matching for the framework adapters (mirrors the PHP MiddlewareSupport trait).

use regex::Regex;

/// except 白名单匹配（语义同 PHP MiddlewareSupport::matchesExcept）：
/// 两侧去首尾 '/'，以 ^(?:pattern)$ 整段匹配；非法正则跳过并告警
pub struct ExceptList {
    patterns: Vec<Regex>,
}

impl ExceptList {
    /// Compile the whitelist once at construction; invalid patterns are skipped with a warning.
    pub fn new(patterns: &[String]) -> Self {
        let mut compiled = Vec::with_capacity(patterns.len());
        for p in patterns {
            let trimmed = p.trim_matches('/');
            // 非捕获组包裹：量词开头的片段（`*`/`/*`/`?` 等）在 Rust 引擎下 `^*$` 会编译成"匹配一切"
            // （`+`/`{n}` 则退化为只匹配空串），而 PCRE 对同类输入编译失败 → fail-closed。
            // `(?:)` 后这类输入同样编译失败，走 warn+skip 对齐 PHP。
            // 同时修正顶层 `|` 的锚定（`^a|b$` 只锚半边；PHP 同病，此处方向为 fail-closed 的有意修正）。
            match Regex::new(&format!("^(?:{trimmed})$")) {
                Ok(re) => compiled.push(re),
                Err(e) => log::warn!("JWT middleware: invalid except pattern {p:?}: {e}"),
            }
        }
        Self { patterns: compiled }
    }

    /// True when the (slash-normalized) request path matches any whitelisted pattern.
    ///
    /// Note: Rust `$` anchors at the absolute end of the string, so `/health$` does **not**
    /// match `"health\n"` (PCRE's `$` would) — stricter, i.e. fail-closed.
    pub fn matches(&self, path: &str) -> bool {
        let path = path.trim_matches('/');
        self.patterns.iter().any(|re| re.is_match(path))
    }

    /// True when no valid pattern was configured (empty input, or every entry was skipped as invalid).
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_with_and_without_slashes() {
        let e = ExceptList::new(&["/api/login".into(), "/health$".into()]);
        assert!(e.matches("/api/login"));
        assert!(e.matches("api/login"));
        assert!(!e.matches("/api/login2"));
        assert!(!e.matches("/healthz"));
        assert!(e.matches("/health"));
    }

    #[test]
    fn patterns_are_regexes_and_quantifier_prefixes_fail_closed() {
        let e = ExceptList::new(&["/api/v[0-9]+/login".into()]);
        assert!(e.matches("/api/v1/login"));
        assert!(!e.matches("/api/vx/login"));

        // 量词开头（PCRE 拒绝）→ 编译失败 → 跳过 → 不匹配任何路径（fail-closed 回归锁）
        assert!(!ExceptList::new(&["/*".into()]).matches("/anything"));
    }

    #[test]
    fn invalid_pattern_skipped_not_panicking() {
        let e = ExceptList::new(&["[bad".into(), "/ok".into()]);
        assert!(!e.matches("/anything"));
        assert!(e.matches("/ok"));
    }

    #[test]
    fn empty_list_never_matches() {
        assert!(!ExceptList::new(&[]).matches("/"));
    }
}
