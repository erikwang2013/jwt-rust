// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
// jwt-rust - JWT authentication for Rust web frameworks
//! Framework-agnostic JWT core (encode / decode / refresh / blacklist).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::config::JwtConfig;
use crate::error::JwtError;
use crate::storage::TokenStorage;

/// 适配层挂进请求 extensions / depot 的 payload 类型（newtype 防止与其他中间件的 Value 撞型）
#[derive(Clone, Debug)]
pub struct JwtPayload(pub Value);

impl JwtPayload {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }
    pub fn jti(&self) -> Option<&str> {
        self.0.get("jti").and_then(Value::as_str)
    }
    pub fn sub(&self) -> Option<&str> {
        self.0.get("sub").and_then(Value::as_str)
    }
}

impl std::ops::Deref for JwtPayload {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 从 "Bearer xxx" 头值取令牌；前缀大小写不敏感、容忍多余空白（同 PHP bearerToken）
pub fn bearer_token(header_value: &str) -> Option<String> {
    let (prefix, rest) = header_value.split_at_checked(7)?;
    if prefix.eq_ignore_ascii_case("Bearer ") {
        let t = rest.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    None
}

pub struct Jwt {
    config: JwtConfig,
    algorithm: Algorithm,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    storage: Arc<dyn TokenStorage>,
}

const SUPPORTED_ALGORITHMS: [&str; 4] = ["HS256", "HS384", "HS512", "RS256"];

impl Jwt {
    pub fn new(config: JwtConfig, storage: Arc<dyn TokenStorage>) -> Result<Self, JwtError> {
        if config.secret_key.len() < 32 {
            return Err(JwtError::config(
                "Secret key must be at least 32 characters (256 bits)",
            ));
        }
        let algorithm = match config.algorithm.as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            other => {
                return Err(JwtError::config(format!(
                    "Unsupported algorithm: {other} (supported: {})",
                    SUPPORTED_ALGORITHMS.join(" / ")
                )));
            }
        };
        let (encoding_key, decoding_key) = match algorithm {
            Algorithm::RS256 => {
                let encoding_key = EncodingKey::from_rsa_pem(config.secret_key.as_bytes())
                    .map_err(|e| JwtError::config(format!("Invalid RSA private key: {e}")))?;
                // DecodingKey::from_rsa_pem 不会从私钥 PEM 提取公钥分量（decode 恒 InvalidSignature）；
                // 经 Jwk 提取公钥分量，并让"传了公钥 PEM"在启动期即报 Config（对齐 PHP 私钥配置可用）
                let jwk =
                    jsonwebtoken::jwk::Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)
                        .map_err(|e| {
                            JwtError::config(format!("Invalid RSA key (private key required): {e}"))
                        })?;
                let decoding_key = DecodingKey::try_from(&jwk)
                    .map_err(|e| JwtError::config(format!("Invalid RSA key: {e}")))?;
                (encoding_key, decoding_key)
            }
            _ => (
                EncodingKey::from_secret(config.secret_key.as_bytes()),
                DecodingKey::from_secret(config.secret_key.as_bytes()),
            ),
        };
        Ok(Self {
            config,
            algorithm,
            encoding_key,
            decoding_key,
            storage,
        })
    }

    pub fn algorithm(&self) -> &str {
        &self.config.algorithm
    }

    pub fn set_token_storage(&mut self, storage: Arc<dyn TokenStorage>) {
        self.storage = storage;
    }

    /// 签发。默认声明（iss/aud/iat/nbf/exp/jti）覆盖用户 payload 同名字段（同 PHP array_merge 语义）；
    /// expire=None 时按 token_type 选择 default_expire / refresh_expire
    pub fn encode<T: Serialize>(
        &self,
        claims: &T,
        expire: Option<u64>,
    ) -> Result<String, JwtError> {
        self.encode_with_header(claims, expire, Header::new(self.algorithm))
    }

    pub fn encode_with_header<T: Serialize>(
        &self,
        claims: &T,
        expire: Option<u64>,
        mut header: Header,
    ) -> Result<String, JwtError> {
        header.alg = self.algorithm; // 忽略调用方指定的 alg（同 PHP unset($headers['alg'])）
        let mut payload = serde_json::to_value(claims).map_err(|e| {
            log::error!("JWT encode: claims not serializable: {e}");
            JwtError::invalid("Invalid payload")
        })?;
        let obj = payload
            .as_object_mut()
            .ok_or_else(|| JwtError::invalid("Invalid payload: must be an object"))?;

        let expire = expire.unwrap_or_else(|| {
            if obj.get("token_type").and_then(Value::as_str) == Some("refresh") {
                self.config.refresh_expire
            } else {
                self.config.default_expire
            }
        });
        let now = now();
        let mut jti = [0u8; 16];
        getrandom::fill(&mut jti).map_err(|e| {
            log::error!("JWT encode: jti generation failed: {e}");
            JwtError::invalid("Token generation failed")
        })?;
        let jti: String = jti.iter().map(|b| format!("{b:02x}")).collect();

        obj.insert("iss".into(), Value::String(self.config.issuer.clone()));
        obj.insert("aud".into(), Value::String(self.config.audience.clone()));
        obj.insert("iat".into(), Value::from(now));
        obj.insert("nbf".into(), Value::from(now));
        let exp = now.saturating_add(expire.min(i64::MAX as u64) as i64);
        obj.insert("exp".into(), Value::from(exp));
        obj.insert("jti".into(), Value::String(jti));

        jsonwebtoken::encode(&header, &payload, &self.encoding_key).map_err(|e| {
            log::error!("JWT encode failed: {e}");
            JwtError::invalid("Token generation failed")
        })
    }

    /// 解码并验证；默认拒绝刷新令牌（allow_refresh 显式放开）
    pub fn decode(&self, token: &str) -> Result<Value, JwtError> {
        self.decode_with(token, false)
    }

    pub fn decode_with(&self, token: &str, allow_refresh: bool) -> Result<Value, JwtError> {
        let mut validation = Validation::new(self.algorithm);
        validation.leeway = self.config.leeway; // 11.1.0 默认 60，必须显式覆盖
        validation.validate_exp = true;
        validation.validate_nbf = true; // 默认 false，须显式开
        validation.validate_aud = false; // iss/aud 手工比对（支持 aud 数组，错误文案对齐 PHP）
        validation.required_spec_claims.clear(); // PHP 允许无 exp 的令牌

        let data =
            jsonwebtoken::decode::<Value>(token, &self.decoding_key, &validation).map_err(|e| {
                use jsonwebtoken::errors::ErrorKind;
                match e.kind() {
                    ErrorKind::ExpiredSignature => {
                        log::info!("Token has expired");
                        JwtError::Expired
                    }
                    _ => {
                        log::error!("JWT decode failed: {e}");
                        JwtError::invalid(e.to_string())
                    }
                }
            })?;
        let payload = data.claims;

        if !self.config.issuer.is_empty()
            && payload.get("iss").and_then(Value::as_str) != Some(self.config.issuer.as_str())
        {
            log::info!("Invalid issuer");
            return Err(JwtError::invalid("Invalid issuer"));
        }
        if !self.config.audience.is_empty() && !aud_matches(&payload, &self.config.audience) {
            log::info!("Invalid audience");
            return Err(JwtError::invalid("Invalid audience"));
        }
        if !allow_refresh && payload.get("token_type").and_then(Value::as_str) == Some("refresh") {
            log::info!("Refresh token cannot be used as an access token");
            return Err(JwtError::invalid(
                "Refresh token cannot be used as an access token",
            ));
        }
        match payload.get("jti") {
            Some(Value::String(jti)) => {
                if self.is_blacklisted_jti(jti)? {
                    log::info!("Token has been blacklisted");
                    return Err(JwtError::Blacklisted);
                }
            }
            Some(v) if !v.is_null() => return Err(JwtError::invalid("Invalid jti")),
            _ => {} // None 或 null：同 PHP isset 语义，跳过检查
        }
        Ok(payload)
    }

    /// Rust 惯用便捷：反序列化为具体类型（保留预留声明检查）
    pub fn decode_as<T: DeserializeOwned>(&self, token: &str) -> Result<T, JwtError> {
        let v = self.decode(token)?;
        serde_json::from_value(v).map_err(|e| {
            log::error!("JWT decode_as: claims shape mismatch: {e}");
            JwtError::invalid("Invalid claims")
        })
    }

    /// 刷新令牌：仅 refresh 类型可换发；旧 jti 未过期时先入黑名单（轮换）
    pub fn refresh(&self, token: &str, new_expire: Option<u64>) -> Result<String, JwtError> {
        let mut payload = self.decode_with(token, true)?;
        if payload.get("token_type").and_then(Value::as_str) != Some("refresh") {
            return Err(JwtError::invalid("Only refresh tokens can be refreshed"));
        }
        let obj = payload
            .as_object_mut()
            .expect("decoded payload is an object");
        let old_exp = obj.get("exp").and_then(Value::as_i64).unwrap_or(0);
        if let Some(jti) = obj.get("jti").and_then(Value::as_str)
            && old_exp > now()
        {
            self.storage.blacklist(jti, old_exp)?;
        }
        for k in ["iat", "nbf", "exp", "jti"] {
            obj.remove(k);
        }
        self.encode(&payload, new_expire)
    }

    /// 将令牌加入黑名单（登出）。已在黑名单或已过期时仍补写记录（幂等）
    pub fn blacklist(&self, token: &str) -> Result<bool, JwtError> {
        match self.decode_with(token, true) {
            Ok(payload) => {
                let Some(jti) = payload.get("jti").and_then(Value::as_str) else {
                    return Ok(false);
                };
                let exp = payload.get("exp").and_then(Value::as_i64).unwrap_or(0);
                self.storage.blacklist(jti, exp)
            }
            Err(e @ (JwtError::Blacklisted | JwtError::Expired)) => {
                log::info!("blacklist: token already {e}, recording anyway");
                let payload = self.payload_without_validation(token)?;
                match (
                    payload.get("jti").and_then(Value::as_str),
                    payload.get("exp").and_then(Value::as_i64),
                ) {
                    (Some(jti), Some(exp)) => self.storage.blacklist(jti, exp),
                    _ => Ok(false),
                }
            }
            Err(e) => {
                log::error!("blacklist failed: {e}");
                Err(e)
            }
        }
    }

    /// 只按 jti 查黑名单，不验证签名（未验证入口，任何输入不得 panic；吞错返 false 同 PHP）
    pub fn is_blacklisted(&self, token: &str) -> bool {
        match self.payload_without_validation(token) {
            Ok(p) => match p.get("jti").and_then(Value::as_str) {
                Some(jti) => self.storage.is_blacklisted(jti).unwrap_or_else(|e| {
                    log::error!("is_blacklisted storage error: {e}");
                    false
                }),
                None => false,
            },
            Err(_) => false,
        }
    }

    /// 解出 payload 而不验证（base64url 解码中间段；jti 非字符串时剔除防伪造打崩存储层）
    pub fn payload_without_validation(&self, token: &str) -> Result<Value, JwtError> {
        use base64::Engine as _;
        let mut parts = token.split('.');
        let (Some(_h), Some(p), Some(_s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwtError::invalid("Invalid token structure"));
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(p))
            .map_err(|_| JwtError::invalid("Invalid token structure"))?;
        let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let mut obj = match parsed {
            Value::Object(map) => map,
            _ => serde_json::Map::new(),
        };
        if obj.get("jti").is_some_and(|v| !v.is_string()) {
            obj.remove("jti");
        }
        Ok(Value::Object(obj))
    }

    pub fn cleanup(&self) -> Result<bool, JwtError> {
        self.storage.cleanup()
    }

    pub fn validate(&self, token: &str) -> bool {
        self.decode(token).is_ok()
    }

    /// 黑名单查询：存储故障按 fail_open 放行（fail-closed 为默认）
    fn is_blacklisted_jti(&self, jti: &str) -> Result<bool, JwtError> {
        match self.storage.is_blacklisted(jti) {
            Ok(v) => Ok(v),
            Err(e @ JwtError::Storage(_)) if self.config.storage.fail_open => {
                log::error!("Blacklist check failed, fail-open enabled: {e}");
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// 测试专用：以绝对 exp 签发。须带 iss/aud，否则在配置了 issuer/audience 的
    /// 实例上解码会先被声明校验拒绝，测不到 exp/leeway 分支。
    #[cfg(test)]
    pub(crate) fn encode_with_exp_for_test<T: Serialize>(
        &self,
        claims: &T,
        exp: i64,
    ) -> Result<String, JwtError> {
        let mut payload = serde_json::to_value(claims).unwrap();
        let obj = payload.as_object_mut().unwrap();
        obj.insert("iss".into(), Value::String(self.config.issuer.clone()));
        obj.insert("aud".into(), Value::String(self.config.audience.clone()));
        obj.insert("exp".into(), Value::from(exp));
        jsonwebtoken::encode(&Header::new(self.algorithm), &payload, &self.encoding_key)
            .map_err(|e| JwtError::invalid(e.to_string()))
    }
}

fn aud_matches(payload: &Value, expected: &str) -> bool {
    match payload.get("aud") {
        Some(Value::Array(list)) => list.iter().any(|v| v.as_str() == Some(expected)),
        Some(Value::String(s)) => s == expected,
        _ => false,
    }
}

#[cfg(test)]
mod tests;
