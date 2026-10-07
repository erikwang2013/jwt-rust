// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! bee-rust integration: `bee_router::Filter`（同步 before，与同步内核零摩擦）。
//!
//! 注册：`Context::dispatch(cache, ttl, &[&JwtFilter::new(auth)], controller)`；
//! 控制器取 payload：`ctx.request.extensions().get::<JwtPayload>()`（`JwtPayload` 挂在 request extensions）。
//! except 路径直接放行且**不注入 payload**（语义同 axum/poem）。

use std::sync::Arc;

use bee_router::context::RouterError;
use bee_router::{Context, Filter};

use super::JwtAuth;
use crate::jwt::bearer_token;
use crate::native::unauthorized_body;

/// bee-rust 适配：实现 `bee_router::Filter`（与 bee-rust 自带 `SecurityFilter` 同款写法，同步 `before`）
pub struct JwtFilter {
    auth: Arc<JwtAuth>,
}

impl JwtFilter {
    pub fn new(auth: Arc<JwtAuth>) -> Self {
        Self { auth }
    }
}

impl Filter for JwtFilter {
    fn before(&self, ctx: &mut Context) -> Result<(), RouterError> {
        if self.auth.matches_except(ctx.request.uri().path()) {
            return Ok(());
        }
        let token = ctx
            .request
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(bearer_token);
        match self.auth.authenticate(token.as_deref()) {
            Ok(payload) => {
                ctx.request.extensions_mut().insert(payload);
                Ok(())
            }
            Err(e) => {
                log::info!(
                    "JWT filter rejected ({} {}): {e}",
                    ctx.request.method(),
                    ctx.request.uri().path()
                );
                // Content-Type 用裸 application/json：与其余七个适配层逐字节一致（poem/salvo 测试同样钉死裸值）
                let _ = ctx.set_header("Content-Type", "application/json");
                ctx.abort(
                    axum::http::StatusCode::UNAUTHORIZED,
                    &unauthorized_body(&e).to_string(),
                );
                Ok(())
            }
        }
    }
}
