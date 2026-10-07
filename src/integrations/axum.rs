// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! axum integration (tower layer over `Route`; mirrors the PHP Webman middleware).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::Router;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use axum::routing::Route;
use tower::{Layer, Service};

use super::JwtAuth;
use crate::jwt::bearer_token;
use crate::native::unauthorized_body;

/// 服务返回的 future：内层 [`Route`] 的 future 或即时的 401 响应
type AuthFuture = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

/// axum 适配：tower 中间件层（对应 PHP Webman\Middleware）
///
/// ```no_run
/// # use std::sync::Arc;
/// # use jwt_rust::integrations::axum::JwtLayer;
/// # let router = axum::Router::<()>::new();
/// # let auth = todo!();
/// let app = JwtLayer::new(Arc::new(auth)).attach(router);
/// ```
///
/// Note: `attach` 经 `route_layer` 只包已注册路由——未匹配路径保持 404、不经鉴权。
/// 若用 `Router::layer(JwtLayer::new(...))`，axum 会把层同时套到 fallback，未匹配路径将以 401（无 token 时）作答；要保 404 语义请用 `attach`。
/// `attach` 对空路由（无任何注册路由）会 panic（axum `route_layer` 的设计），请至少注册一条路由后再挂。
#[derive(Clone)]
pub struct JwtLayer {
    auth: Arc<JwtAuth>,
}

impl JwtLayer {
    pub fn new(auth: Arc<JwtAuth>) -> Self {
        Self { auth }
    }

    /// 一步挂载：只包已注册路由（保持 404 语义）
    pub fn attach<S: Clone + Send + Sync + 'static>(self, router: Router<S>) -> Router<S> {
        router.route_layer(self)
    }
}

impl Layer<Route> for JwtLayer {
    type Service = JwtService;

    fn layer(&self, inner: Route) -> Self::Service {
        JwtService {
            inner,
            auth: self.auth.clone(),
        }
    }
}

/// 鉴权服务：放行时把 [`JwtPayload`](crate::jwt::JwtPayload) 挂进请求 extensions 再交给内层路由
/// （404 路径不经此层；except 白名单直接跳过鉴权）
#[derive(Clone)]
pub struct JwtService {
    inner: Route,
    auth: Arc<JwtAuth>,
}

impl Service<Request> for JwtService {
    type Response = Response;
    type Error = Infallible;
    type Future = AuthFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // `Route` 对 Request<B> 泛型实现 Service，需限定 B=Body（Request）以消歧
        <Route as Service<Request>>::poll_ready(&mut self.inner, cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let auth = self.auth.clone();
        let not_ready_inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, not_ready_inner);

        if !auth.matches_except(req.uri().path()) {
            let token = req
                .headers()
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(bearer_token);
            match auth.authenticate(token.as_deref()) {
                Ok(payload) => {
                    req.extensions_mut().insert(payload);
                }
                Err(e) => {
                    log::info!(
                        "JWT middleware rejected ({} {}): {e}",
                        req.method(),
                        req.uri().path()
                    );
                    let resp = (
                        axum::http::StatusCode::UNAUTHORIZED,
                        axum::Json(unauthorized_body(&e)),
                    )
                        .into_response();
                    return Box::pin(std::future::ready(Ok(resp)));
                }
            }
        }
        Box::pin(<Route as Service<Request>>::call(&mut inner, req))
    }
}
