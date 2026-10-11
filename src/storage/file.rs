// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! File-system blacklist driver (atomic writes, probabilistic GC).

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::TokenStorage;
use crate::error::JwtError;

#[derive(Serialize, Deserialize)]
struct Entry {
    jti: String,
    expire_time: i64,
    created_at: i64,
}

/// 文件系统黑名单（原子写 tmp+rename、概率 GC、非 hex jti 转 hex 文件名）
#[derive(Debug)]
pub struct FileTokenStorage {
    path: PathBuf,
    gc_probability: f64,
}

impl FileTokenStorage {
    pub fn new(path: Option<PathBuf>) -> Result<Self, JwtError> {
        // 空 path 视同未配置：env 侧有 is_empty → None 归一化，TOML 的 path = "" 在此对齐
        // （否则 "" 经递归 create 静默成功，落盘落到进程 CWD）
        let path = path
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::env::temp_dir().join("jwt_blacklist"));
        if !path.is_dir() {
            // 仅在新建时设 0700（已存在目录不动其权限）；
            // DirBuilder::mode 在 mkdir 时应用，显式 set_permissions 兜底极端 umask
            #[cfg(unix)]
            {
                use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
                let mut b = fs::DirBuilder::new();
                b.recursive(true).mode(0o700);
                b.create(&path).map_err(|e| {
                    JwtError::storage(format!(
                        "Cannot create storage directory: {} ({e})",
                        path.display()
                    ))
                })?;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
            }
            #[cfg(not(unix))]
            fs::create_dir_all(&path).map_err(|e| {
                JwtError::storage(format!(
                    "Cannot create storage directory: {} ({e})",
                    path.display()
                ))
            })?;
        } else {
            // 已存在目录（含他人预创建）：先拒绝 group/other 可写的目录（他人可删除/伪造黑名单条目），
            // 再做写入探测——属主不符（EACCES）、只读挂载等在此启动期显式失败，
            // 而不是等到每请求静默放行（读错误 → Ok(false)）或报错。
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&path)
                    .map_err(|e| {
                        JwtError::storage(format!(
                            "Cannot stat storage directory: {} ({e})",
                            path.display()
                        ))
                    })?
                    .permissions()
                    .mode();
                if mode & 0o022 != 0 {
                    return Err(JwtError::storage(format!(
                        "Storage directory {} is writable by group/other (mode {:o}); chmod 700 it or configure another path",
                        path.display(),
                        mode & 0o777
                    )));
                }
            }
            let probe = path.join(format!(".jwt_write_probe_{}", std::process::id()));
            fs::write(&probe, b"").map_err(|e| {
                JwtError::storage(format!(
                    "Storage directory {} is not writable: {e}",
                    path.display()
                ))
            })?;
            let _ = fs::remove_file(&probe);
        }
        Ok(Self {
            path,
            gc_probability: 0.1,
        })
    }

    pub fn with_gc_probability(mut self, p: f64) -> Self {
        self.gc_probability = p.clamp(0.0, 1.0);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn file_path(&self, jti: &str) -> PathBuf {
        // 非 hex 转 hex 文件名：杜绝路径穿越，且不改变本库 hex jti 的文件名。
        // 空 jti 无 hex 转写结果（会成裸 ".json"），按 sha256 摘要落名，与 sanitize_key_sha256 的空串处理对齐。
        // 已知边角（方向为过度拉黑）：非 hex jti 的转写名与"恰好等于该转写串"的另一 hex jti 撞名。
        let name = if !jti.is_empty() && jti.bytes().all(|b| b.is_ascii_hexdigit()) {
            jti.to_string()
        } else if jti.is_empty() {
            use sha2::{Digest, Sha256};
            hex_encode(Sha256::digest(jti.as_bytes()))
        } else {
            hex_encode(jti.bytes())
        };
        self.path.join(format!("{name}.json"))
    }

    fn gc(&self) {
        if self.gc_probability <= 0.0 {
            return;
        }
        let mut buf = [0u8; 8];
        if getrandom::fill(&mut buf).is_err() {
            return;
        }
        let r = u64::from_le_bytes(buf) as f64 / u64::MAX as f64;
        if r < self.gc_probability {
            let _ = self.cleanup();
        }
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hex_encode(bytes: impl IntoIterator<Item = u8>) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

impl TokenStorage for FileTokenStorage {
    fn blacklist(&self, jti: &str, expire_time: i64) -> Result<bool, JwtError> {
        let now = now();
        if expire_time <= now {
            return Ok(true); // 已过期无需记录；直接比较，避免减法在极端值下溢出
        }
        let file = self.file_path(jti);
        let data = serde_json::to_vec(&Entry {
            jti: jti.into(),
            expire_time,
            created_at: now,
        })
        .map_err(|e| JwtError::storage(format!("Failed to serialize blacklist entry: {e}")))?;
        // 原子写：同目录临时文件 + rename，并发读永不见半截 JSON。
        // tmp 名随机后缀（4 字节随机）：同进程并发写同一 jti 互不踩踏（getrandom 失败回退 pid）
        let mut rnd = [0u8; 4];
        if getrandom::fill(&mut rnd).is_err() {
            rnd = (std::process::id() as u32).to_le_bytes();
        }
        let tmp = file.with_extension(format!("json.tmp.{:08x}", u32::from_le_bytes(rnd)));
        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()
        };
        if let Err(e) = write().and_then(|_| fs::rename(&tmp, &file)) {
            let _ = fs::remove_file(&tmp);
            return Err(JwtError::storage(format!(
                "Failed to write blacklist file: {} ({e})",
                file.display()
            )));
        }
        self.gc();
        Ok(true)
    }

    fn is_blacklisted(&self, jti: &str) -> Result<bool, JwtError> {
        let file = self.file_path(jti);
        // 读错误/解析失败静默视为未拉黑（可用性优先的取舍）；仅日志便于排障
        let content = match fs::read_to_string(&file) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    log::warn!("JWT file storage: cannot read {}: {e}", file.display());
                }
                return Ok(false);
            }
        };
        let entry = match serde_json::from_str::<Entry>(&content) {
            Ok(entry) => entry,
            Err(e) => {
                log::warn!("JWT file storage: corrupt entry {}: {e}", file.display());
                return Ok(false);
            }
        };
        if now() > entry.expire_time {
            if let Err(e) = fs::remove_file(&file) {
                log::warn!(
                    "JWT file storage: failed to remove expired {}: {e}",
                    file.display()
                );
            }
            return Ok(false);
        }
        Ok(true)
    }

    fn cleanup(&self) -> Result<bool, JwtError> {
        let now = now();
        let Ok(dir) = fs::read_dir(&self.path) else {
            return Ok(true);
        };
        for e in dir.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".json") {
                if let Ok(content) = fs::read_to_string(&p)
                    && let Ok(entry) = serde_json::from_str::<Entry>(&content)
                    && now > entry.expire_time
                {
                    let _ = fs::remove_file(&p);
                }
            } else if name.contains(".json.tmp.") {
                // 写崩残留的临时文件，1 小时后回收
                if let Ok(meta) = e.metadata()
                    && let Ok(modified) = meta.modified()
                    && now.saturating_sub(
                        modified
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(now),
                    ) > 3600
                {
                    let _ = fs::remove_file(&p);
                }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::TokenStorage;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jwt_rust_test_{tag}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn write_and_query() {
        let s = FileTokenStorage::new(Some(tmp_dir("fwq")))
            .unwrap()
            .with_gc_probability(0.0);
        assert!(!s.is_blacklisted("aa11").unwrap());
        assert!(s.blacklist("aa11", now() + 60).unwrap());
        assert!(s.is_blacklisted("aa11").unwrap());
    }

    #[test]
    fn expired_entry_write_is_noop_and_read_is_false() {
        let dir = tmp_dir("exp");
        let s = FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(0.0);
        assert!(s.blacklist("bb", now() - 5).unwrap());
        assert!(!s.is_blacklisted("bb").unwrap());
        assert!(
            !dir.join("bb.json").exists(),
            "expired jti must not be written"
        );
    }

    #[test]
    fn cleanup_removes_expired() {
        let dir = tmp_dir("cl");
        let s = FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(0.0);
        s.blacklist("cc", now() + 60).unwrap();
        // 手工改一个过期条目落盘
        let p = dir.join("dd.json");
        fs::write(&p, r#"{"jti":"dd","expire_time":1,"created_at":1}"#).unwrap();
        s.cleanup().unwrap();
        assert!(!p.exists());
        assert!(s.is_blacklisted("cc").unwrap());
    }

    #[test]
    fn non_hex_jti_filename_is_hex() {
        let dir = tmp_dir("hex");
        let s = FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(0.0);
        s.blacklist("../../evil", now() + 60).unwrap();
        let files: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], "2e2e2f2e2e2f6576696c.json");
    }

    #[test]
    fn gc_probability_one_cleans() {
        let dir = tmp_dir("gc");
        let s = FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(1.0);
        let stale = dir.join("ee.json");
        fs::write(&stale, r#"{"jti":"ee","expire_time":1,"created_at":1}"#).unwrap();
        s.blacklist("ff", now() + 60).unwrap(); // 触发概率 1.0 的 GC
        assert!(!stale.exists());
    }

    #[test]
    fn cleanup_removes_stale_tmp_and_keeps_fresh() {
        use std::time::Duration;
        let dir = tmp_dir("tmpg");
        let s = FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(0.0);
        let stale = dir.join("aa.json.tmp.0001");
        let fresh = dir.join("bb.json.tmp.0002");
        fs::write(&stale, "x").unwrap();
        fs::write(&fresh, "x").unwrap();
        fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(7200))
            .unwrap();
        s.cleanup().unwrap();
        assert!(!stale.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn write_leaves_no_tmp_residue() {
        let dir = tmp_dir("res");
        let s = FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(0.0);
        s.blacklist("ab12", now() + 60).unwrap();
        let residue: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(residue.is_empty(), "unexpected tmp residue: {residue:?}");
    }

    #[test]
    fn expired_on_read_is_deleted_from_disk() {
        let dir = tmp_dir("ronly");
        let s = FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(0.0);
        let p = dir.join("cc11.json");
        fs::write(&p, r#"{"jti":"cc11","expire_time":1,"created_at":1}"#).unwrap();
        assert!(!s.is_blacklisted("cc11").unwrap());
        assert!(!p.exists(), "expired file should be removed on read");
    }

    #[cfg(unix)]
    #[test]
    fn dir_mode_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("mode");
        let _s = FileTokenStorage::new(Some(dir.clone())).unwrap();
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn new_none_uses_default_dir() {
        let s = FileTokenStorage::new(None).unwrap();
        assert!(s.path().ends_with("jwt_blacklist"));
    }

    #[test]
    fn empty_path_falls_back_to_default_dir() {
        // TOML path = "" 与 env 的空值归一化对齐：不得落到进程 CWD
        let s = FileTokenStorage::new(Some(PathBuf::from(""))).unwrap();
        assert!(s.path().ends_with("jwt_blacklist"));
    }

    #[test]
    fn empty_jti_gets_digest_filename() {
        let dir = tmp_dir("emptyjti");
        let s = FileTokenStorage::new(Some(dir.clone()))
            .unwrap()
            .with_gc_probability(0.0);
        assert!(s.blacklist("", now() + 60).unwrap());
        assert!(s.is_blacklisted("").unwrap());
        let files: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].len(), 64 + ".json".len()); // sha256 摘要名，非裸 ".json"
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_group_writable_dir_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("perm_bad");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        // 他人可写 = 可删除/伪造黑名单条目 → 启动期拒绝
        let e = FileTokenStorage::new(Some(dir.clone())).unwrap_err();
        assert!(matches!(e, JwtError::Storage(_)), "got {e:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_private_dir_is_accepted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("perm_ok");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let s = FileTokenStorage::new(Some(dir.clone())).unwrap();
        assert!(s.blacklist("a1", now() + 60).unwrap());
        assert!(s.is_blacklisted("a1").unwrap());
        let _ = fs::remove_dir_all(&dir);
    }
}
