// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! poem integration (`Route::new().at(...).with(JwtMiddleware::new(auth))`).
//!
//! payload 放行时挂进请求 extensions（`req.extensions().get::<JwtPayload>()`），拒绝时统一 401 JSON。

use std::sync::Arc;

use poem::middleware::Middleware;
use poem::{Endpoint, IntoResponse, Request, Response};

use super::JwtAuth;
use crate::jwt::bearer_token;
use crate::native::unauthorized_body;

/// poem 适配：`Route::new().at("/api/me", me).with(JwtMiddleware::new(auth))`（`.with` 来自 `EndpointExt`）
///
/// Note: `.with` 覆盖该 endpoint 收到的**所有**请求——未匹配路径在无 token 时同样得 401 而非 404（与 actix `App::wrap` 同理；poem 无 `route_layer` 等价物）。
/// 需要 404 语义时把中间件挂到单条路由：`Route::new().at("/api/me", me.with(JwtMiddleware::new(auth)))`，公开路由不挂即可。
/// 用 `nest` 圈子树要当心（**中间件挂在 nest 子树内时**）：`nest` 默认剥离前缀，中间件里 `req.uri().path()` 是剥离后的路径（`/api/login` → `/login`），except 名单须按剥离子树书写；`nest_no_strip` 则内层路由要写全路径。（`.with` 挂在外层 Route 上则看到全路径，两种挂法结论相反。）
#[derive(Clone)]
pub struct JwtMiddleware {
    auth: Arc<JwtAuth>,
}

impl JwtMiddleware {
    pub fn new(auth: Arc<JwtAuth>) -> Self {
        Self { auth }
    }
}

impl<E: Endpoint> Middleware<E> for JwtMiddleware {
    type Output = JwtEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        JwtEndpoint {
            inner: ep,
            auth: self.auth.clone(),
        }
    }
}

/// 鉴权端点：except 路径直接放行（即使携带有效 token 也不注入 payload）；校验通过时注入 payload 再交还内层；拒绝时 401 JSON。
pub struct JwtEndpoint<E> {
    inner: E,
    auth: Arc<JwtAuth>,
}

impl<E: Endpoint> Endpoint for JwtEndpoint<E> {
    type Output = Response;

    async fn call(&self, mut req: Request) -> poem::Result<Self::Output> {
        if self.auth.matches_except(req.uri().path()) {
            return Ok(self.inner.call(req).await?.into_response());
        }
        let token = req
            .headers()
            .get(poem::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(bearer_token);
        match self.auth.authenticate(token.as_deref()) {
            Ok(payload) => {
                req.extensions_mut().insert(payload);
                Ok(self.inner.call(req).await?.into_response())
            }
            Err(e) => {
                // 与 axum/actix/rocket 家族统一格式
                log::info!(
                    "JWT middleware rejected ({} {}): {e}",
                    req.method(),
                    req.uri().path()
                );
                // 统一 401 JSON 体（契约：crate::native::unauthorized_body；Value 的 Display 即紧凑 JSON）。
                // 不用 poem::web::Json：它会写成 application/json; charset=utf-8，破坏与其余 7 个适配层的响应头一致性。
                Ok(poem::Response::builder()
                    .status(poem::http::StatusCode::UNAUTHORIZED)
                    .content_type("application/json")
                    .body(unauthorized_body(&e).to_string()))
            }
        }
    }
}
