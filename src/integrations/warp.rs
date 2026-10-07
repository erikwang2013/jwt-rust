// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! warp integration: `with_jwt` 过滤器把 payload 透传给下游（warp 无 extensions 惯例）。
//!
//! Note: warp 无「路由级跳过」过滤器语义——except 路由请直接不挂 `with_jwt`；
//! 把 except 路径接上 `with_jwt` 会得到显式拒绝（提示用法错误）。失败以 `JwtRejection`
//! 拒绝，应用侧用 `recover` 按 `j.status` 渲染（鉴权失败 401 / 误用 500）（见 tests/warp_test.rs）；**`recover` 是必需件**：
//! 未 recover 时 warp 把 `JwtRejection` 当陌生自定义拒绝，渲染 500 `text/plain`
//! （`Unhandled rejection: …`；warp 0.4 的 `Reject` 无 `status()` 可覆盖，状态只能由 `recover` 决定）。
//! except 名单按全路径书写（`as_str()` 不含 query），与其余适配层一致。

use std::sync::Arc;

use serde_json::Value;
use warp::Filter;

use super::JwtAuth;
use crate::jwt::{JwtPayload, bearer_token};
use crate::native::unauthorized_body;

/// warp 适配：`path.and(with_jwt(auth)).map(|p: JwtPayload| ...)`
///
/// Note: `warp::path::FullPath` 是提取类型、不是过滤器；过滤器为 `warp::path::full()`（Error=Infallible）。
/// 取头用 `header::headers_cloned()`（Error=Infallible）而非 `header::optional::<String>`——
/// 后者对含非可见 ASCII 的头值以 warp 内建 `InvalidHeader` 拒绝（400 text/plain），与其余七层 `to_str().ok() → 401` 分歧。
/// `path::full()` 与 `headers_cloned` 组合后，Error 只来自 `and_then` 回吐的 Rejection。
pub fn with_jwt(
    auth: Arc<JwtAuth>,
) -> impl Filter<Extract = (JwtPayload,), Error = warp::Rejection> + Clone {
    warp::path::full()
        .and(warp::method())
        .and(warp::header::headers_cloned())
        .and_then(move |path: warp::path::FullPath, method: warp::http::Method, headers: warp::http::HeaderMap| {
            let auth = auth.clone();
            async move {
                if auth.matches_except(path.as_str()) {
                    log::error!("JWT filter: except path {} must not mount with_jwt", path.as_str());
                    return Err(warp::reject::custom(JwtRejection {
                        status: warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        body: serde_json::json!({"code":500,"msg":"except paths should not use with_jwt","data":null}),
                    }));
                }
                let token = headers
                    .get(warp::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(bearer_token);
                auth.authenticate(token.as_deref()).map_err(|e| {
                    log::info!("JWT filter rejected ({} {}): {e}", method, path.as_str());
                    warp::reject::custom(JwtRejection { status: warp::http::StatusCode::UNAUTHORIZED, body: unauthorized_body(&e) })
                })
            }
        })
}

/// 携带 HTTP 状态与 JSON 体的自定义拒绝（应用侧 `recover` 中 `rej.find::<JwtRejection>()` 取用）
#[derive(Debug, Clone)]
pub struct JwtRejection {
    pub status: warp::http::StatusCode,
    pub body: Value,
}

impl warp::reject::Reject for JwtRejection {}
