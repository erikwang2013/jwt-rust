// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! SQLite blacklist driver (v1 of the `database` storage; other SQL backends implement `TokenStorage`).

use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

use super::TokenStorage;
use crate::error::JwtError;

/// SQLite 黑名单（v1 的 database 驱动；MySQL/PG 实现 TokenStorage trait 即可）。
/// 表：jti TEXT PRIMARY KEY, expire_time INTEGER NOT NULL, created_at INTEGER；写入为幂等 upsert
pub struct DatabaseTokenStorage {
    // ponytail: 单连接 + Mutex（rusqlite 默认 busy_timeout 5s，优于 PHP PDO 的 0）；高并发换连接池；多进程共享同一文件需 WAL（要求 FS 支持共享内存）
    conn: Mutex<Connection>,
    table: String,
}

impl DatabaseTokenStorage {
    /// `path` 为 SQLite 路径或 URI（如 `file:x?mode=memory&cache=shared`），`None` 为私有内存库。
    pub fn new(
        path: Option<String>,
        table_name: &str,
        auto_create: bool,
    ) -> Result<Self, JwtError> {
        if !valid_table_name(table_name) {
            return Err(JwtError::config(format!(
                "Invalid table name: {table_name}"
            )));
        }
        let conn = match path {
            Some(p) => Connection::open(p),
            None => Connection::open_in_memory(),
        }
        .map_err(|e| JwtError::storage(format!("Database open failed: {e}")))?;
        let s = Self {
            conn: Mutex::new(conn),
            table: table_name.to_string(),
        };
        if auto_create {
            s.exec(&format!(
                "CREATE TABLE IF NOT EXISTS {} (jti TEXT PRIMARY KEY, expire_time INTEGER NOT NULL, created_at INTEGER)",
                s.table
            ))?;
        }
        Ok(s)
    }

    /// 取连接锁；中毒（panic 时持有）后继续用原连接：语句均为 autocommit、无未完成事务，可安全复用。
    /// clear_poison 必须调用（同 redis 驱动）：否则每次 lock() 都走 Err 分支、中毒标志永久残留。
    fn conn(&self) -> MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                self.conn.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    fn exec(&self, sql: &str) -> Result<(), JwtError> {
        self.conn().execute(sql, []).map(|_| ()).map_err(db_err)
    }
}

fn db_err(e: rusqlite::Error) -> JwtError {
    JwtError::storage(format!("Database operation failed: {e}"))
}

/// 表名白名单：字母/下划线开头，仅字母数字下划线（防 SQL 注入进标识符位）
fn valid_table_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl TokenStorage for DatabaseTokenStorage {
    fn blacklist(&self, jti: &str, expire_time: i64) -> Result<bool, JwtError> {
        self.conn()
            .execute(
                &format!(
                    "INSERT INTO {} (jti, expire_time, created_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(jti) DO UPDATE SET expire_time = excluded.expire_time",
                    self.table
                ),
                rusqlite::params![jti, expire_time, crate::jwt::now()],
            )
            .map_err(db_err)?;
        Ok(true)
    }

    fn is_blacklisted(&self, jti: &str) -> Result<bool, JwtError> {
        let c = self.conn();
        let mut stmt = c
            .prepare(&format!(
                "SELECT 1 FROM {} WHERE jti = ?1 AND expire_time > ?2",
                self.table
            ))
            .map_err(db_err)?;
        // 表不存在等错误必须冒泡（静默 false 会放行本应拦截的令牌）
        stmt.exists(rusqlite::params![jti, crate::jwt::now()])
            .map_err(db_err)
    }

    fn cleanup(&self) -> Result<bool, JwtError> {
        self.conn()
            .execute(
                &format!("DELETE FROM {} WHERE expire_time <= ?1", self.table),
                rusqlite::params![crate::jwt::now()],
            )
            .map(|_| true)
            .map_err(db_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::TokenStorage;

    fn storage(name: &str) -> DatabaseTokenStorage {
        DatabaseTokenStorage::new(
            Some(format!("file:jwt_rust_{name}?mode=memory&cache=shared")),
            "jwt_blacklist",
            true,
        )
        .unwrap()
    }

    #[test]
    fn insert_query_cleanup_and_idempotency() {
        let s = storage("db1");
        let now = crate::jwt::now();
        assert!(s.blacklist("j1", now + 60).unwrap());
        assert!(s.blacklist("j1", now + 120).unwrap()); // 幂等：只更新过期时间
        assert!(s.is_blacklisted("j1").unwrap());
        assert!(!s.is_blacklisted("nope").unwrap());
        assert!(s.cleanup().unwrap());
        assert!(s.is_blacklisted("j1").unwrap()); // 未过期仍在
        assert!(s.blacklist("old", 1).unwrap());
        s.cleanup().unwrap();
        assert!(!s.is_blacklisted("old").unwrap()); // 过期条目被清理
    }

    #[test]
    fn invalid_table_name_rejected() {
        // 不用 unwrap_err()：那要求 Ok 侧 Debug，而本类型（同 redis/file 驱动）不派生 Debug
        let Err(e) = DatabaseTokenStorage::new(None, "bad name;drop", false) else {
            panic!("invalid table name must be rejected");
        };
        assert!(matches!(e, JwtError::Config(_)));
    }

    #[test]
    fn auto_create_off_requires_existing_table() {
        // 内存库 + 不建表 → 查询必须报 Storage 错误（不得静默 false —— 静默会放行本应拦截的令牌）
        let s = DatabaseTokenStorage::new(
            Some("file:jwt_rust_nc?mode=memory&cache=shared".into()),
            "t_missing",
            false,
        )
        .unwrap();
        let e = s.is_blacklisted("x").unwrap_err();
        assert!(matches!(e, JwtError::Storage(_)));
    }

    #[test]
    fn file_persistence_and_reopen_without_auto_create() {
        let dir = std::env::temp_dir().join(format!("jwt_rust_db_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("blacklist.db");
        let path = db.to_string_lossy().into_owned();
        let now = crate::jwt::now();

        {
            let s = DatabaseTokenStorage::new(Some(path.clone()), "jwt_blacklist", true).unwrap();
            assert!(s.blacklist("f1", now + 60).unwrap());
        } // drop：连接关闭

        // 重开（auto_create=false）：表已存在，数据仍在（跨连接持久化契约）
        let s = DatabaseTokenStorage::new(Some(path), "jwt_blacklist", false).unwrap();
        assert!(s.is_blacklisted("f1").unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_memory_default_path_roundtrip() {
        let s = DatabaseTokenStorage::new(None, "jwt_blacklist", true).unwrap();
        let now = crate::jwt::now();
        assert!(s.blacklist("m1", now + 60).unwrap());
        assert!(s.is_blacklisted("m1").unwrap());
    }
}
