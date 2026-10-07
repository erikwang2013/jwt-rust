// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! e-cat gRPC 拦截器：从 metadata `authorization` 取 Bearer → 完整校验 → claims 注入请求 extensions。
//!
//! 挂载：`InterceptorLayer::new(JwtInterceptor::new(auth)).layer(svc)`（`tonic::service::InterceptorLayer`）
//! 后交 e-cat-transport-grpc 的 `Routes::add_service`；tonic 0.14 已无旧版 `tonic::service::interceptor()` 自由函数。
//! 失败以 `Status::unauthenticated(user_message)` 返回（gRPC 惯例，无 HTTP 体）。
//!
//! 无 except 白名单：`Interceptor::call` 只见 metadata/extensions（tonic `InterceptedService::call`
//! 在调用拦截器前剥离 URI/method，日志因此无 `(method path)`）；`middleware.except` 对 gRPC 不生效，
//! 公开方法=该服务不挂本层（`InterceptorLayer::new(..).layer(svc)` 按服务挂载；全局挂载会连 health/reflection 一并拦）。

use std::sync::Arc;

use tonic::service::Interceptor;
use tonic::{Request, Status};

use crate::integrations::JwtAuth;
use crate::jwt::bearer_token;

/// e-cat gRPC 拦截器（同一 `JwtAuth` 门面：校验/黑名单/拒刷新令牌与 HTTP 层完全一致）
///
/// `Clone`：`Routes::add_service` 要求服务 `Clone`，而 `InterceptedService` 仅在 `I: Clone` 时可 clone。
#[derive(Clone)]
pub struct JwtInterceptor {
    auth: Arc<JwtAuth>,
}

impl JwtInterceptor {
    pub fn new(auth: Arc<JwtAuth>) -> Self {
        Self { auth }
    }
}

impl Interceptor for JwtInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(bearer_token);
        match self.auth.authenticate(token.as_deref()) {
            Ok(payload) => {
                request.extensions_mut().insert(payload);
                Ok(request)
            }
            Err(e) => {
                log::info!("JWT interceptor rejected: {e}");
                Err(Status::unauthenticated(e.user_message()))
            }
        }
    }
}
