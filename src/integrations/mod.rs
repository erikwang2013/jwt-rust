// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! Shared layer for the framework integrations: one `JwtAuth` assembled from config.

use std::sync::Arc;

use crate::config::JwtConfig;
use crate::error::JwtError;
use crate::factory::JwtFactory;
use crate::jwt::{Jwt, JwtPayload};
use crate::middleware_support::ExceptList;

#[cfg(feature = "actix")]
pub mod actix;
#[cfg(any(feature = "axum", feature = "ecat"))]
pub mod axum;
#[cfg(feature = "bee-rust")]
pub mod bee_rust;
#[cfg(feature = "ecat")]
pub mod ecat;
#[cfg(feature = "poem")]
pub mod poem;
#[cfg(feature = "rocket")]
pub mod rocket;
#[cfg(feature = "salvo")]
pub mod salvo;
#[cfg(feature = "warp")]
pub mod warp;

/// 八框架适配层共享的鉴权门面：一次装配 Jwt + except 名单
///
/// 契约：适配层的 401 响应体一律走 [`crate::native::unauthorized_body`]，不得各自重写；
/// `authenticate` 返回的 [`JwtPayload`] 由各框架挂进 extensions / depot。
/// 适配层统一以 `Arc<JwtAuth>` 持有/接收（构造器签名 new(`Arc<JwtAuth>`)）；需要 Clone 的 state/中间件直接 clone 这个 Arc。
/// token 提取统一走 crate::bearer_token（大小写不敏感、容忍空白），勿手写 split。
#[derive(Clone)]
pub struct JwtAuth {
    jwt: Arc<Jwt>,
    except: Arc<ExceptList>,
}

impl JwtAuth {
    pub fn from_config(config: JwtConfig) -> Result<Self, JwtError> {
        let except = ExceptList::new(&config.middleware.except);
        let jwt = JwtFactory::from_config(config)?;
        Ok(Self {
            jwt: Arc::new(jwt),
            except: Arc::new(except),
        })
    }

    pub fn matches_except(&self, path: &str) -> bool {
        self.except.matches(path)
    }

    /// token=None/空 → "Token not provided"；否则完整校验并返回 payload
    /// （decode 内含黑名单 / 刷新令牌拒绝）
    pub fn authenticate(&self, token: Option<&str>) -> Result<JwtPayload, JwtError> {
        let token = token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| JwtError::invalid("Token not provided"))?;
        self.jwt.decode(token).map(JwtPayload)
    }

    pub fn jwt(&self) -> &Jwt {
        &self.jwt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JwtConfig;

    fn auth() -> JwtAuth {
        JwtAuth::from_config(JwtConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn authenticate_and_except() {
        let a = auth();
        let token = a
            .jwt()
            .encode(&serde_json::json!({"user_id": 7}), None)
            .unwrap();
        let p = a.authenticate(Some(&token)).unwrap();
        assert_eq!(p.get("user_id").unwrap(), 7);
        assert!(
            matches!(a.authenticate(None), Err(crate::error::JwtError::Invalid(m)) if m.contains("not provided"))
        );
    }

    #[test]
    fn except_list_from_config() {
        let a = JwtAuth::from_config(JwtConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            middleware: crate::config::MiddlewareConfig {
                except: vec!["/api/login".into()],
            },
            ..Default::default()
        })
        .unwrap();
        assert!(a.matches_except("/api/login"));
        assert!(!a.matches_except("/api/user"));
    }

    #[test]
    fn jwt_auth_is_send_sync_clone() {
        fn assert_bounds<T: Send + Sync + Clone + 'static>() {}
        assert_bounds::<JwtAuth>();
    }
}
