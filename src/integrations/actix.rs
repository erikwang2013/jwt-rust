// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! actix-web integration (App::wrap middleware; mirrors the PHP Webman middleware).

use std::sync::Arc;

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse, Transform};
use actix_web::{Error, HttpMessage};

use super::JwtAuth;
use crate::jwt::bearer_token;
use crate::native::unauthorized_body;

/// actix-web 适配（`App::wrap(Jwt::new(auth))` 注册）
///
/// Note: `App::wrap` 覆盖**所有**请求——未匹配路径在无 token 时也会得 401 而非 404（actix 无 `route_layer` 等价物）。
/// 需要 404 语义时把守卫挂到 `Scope::wrap`/`Resource::wrap`，或用 `App::default_service` 兜底。
#[derive(Clone)]
pub struct Jwt {
    auth: Arc<JwtAuth>,
}

impl Jwt {
    pub fn new(auth: Arc<JwtAuth>) -> Self {
        Self { auth }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Jwt
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>
        + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = JwtMiddleware<S>;
    type InitError = ();
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(JwtMiddleware {
            service,
            auth: self.auth.clone(),
        }))
    }
}

/// 鉴权中间件服务（Transform 产物；放行时注入 payload、经 EitherBody 交还内层响应，拒绝时 401 JSON）。
pub struct JwtMiddleware<S> {
    service: S,
    auth: Arc<JwtAuth>,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for JwtMiddleware<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>
        + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth = self.auth.clone();
        let (http_req, payload) = req.into_parts();
        if auth.matches_except(http_req.path()) {
            let req = ServiceRequest::from_parts(http_req, payload);
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await.map(|r| r.map_into_left_body()) });
        }
        let token = http_req
            .headers()
            .get(actix_web::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(bearer_token);
        match auth.authenticate(token.as_deref()) {
            Ok(jwt_payload) => {
                http_req.extensions_mut().insert(jwt_payload);
                let req = ServiceRequest::from_parts(http_req, payload);
                let fut = self.service.call(req);
                Box::pin(async move { fut.await.map(|r| r.map_into_left_body()) })
            }
            Err(e) => {
                // 与其余适配层统一格式（3.1 审查沉淀）
                log::info!(
                    "JWT middleware rejected ({} {}): {e}",
                    http_req.method(),
                    http_req.path()
                );
                let resp = actix_web::HttpResponse::Unauthorized()
                    .json(unauthorized_body(&e))
                    .map_into_right_body();
                Box::pin(async move { Ok(ServiceResponse::new(http_req, resp)) })
            }
        }
    }
}
