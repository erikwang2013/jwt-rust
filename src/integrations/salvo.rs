// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! salvo integration (`Router::hoop(JwtHoop::new(auth))`); payload 进 depot。

use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::http::header::{CONTENT_TYPE, HeaderValue};
use salvo::prelude::*;

use super::JwtAuth;
use crate::jwt::bearer_token;
use crate::native::unauthorized_body;

/// salvo 适配：`Router::hoop(JwtHoop::new(auth))`；payload 经 `depot.insert_typed`，处理器用 `depot.get_typed::<JwtPayload>()` 读取
/// （`inject`/`obtain` 自 0.94 起为 deprecated 别名，1.0.1 下用会触发 `deprecated` 警告）。
///
/// Note: `hoop` 挂在哪层就只对哪层子树生效——挂在挂载 `api/*` 的路由上和挂在根 `Router::new()` 上，`req.uri().path()` 看到的都是完整路径
/// （`with_path` 不剥离前缀，这点与 poem `nest` 相反）；except 名单一律按全路径书写。
/// 挂在 `Router` 上的 hoop 只在路由匹配成功时运行：未匹配路径保持 404（路径匹配但方法不匹配则 405），
/// 与 axum attach/route_layer 同理，**不同于** actix `App::wrap`、poem `.with`。
/// 需要整站覆盖（未匹配路径也 401）请改挂服务层：`Service::new(router).hoop(JwtHoop::new(auth))`。
#[derive(Clone)]
pub struct JwtHoop {
    auth: Arc<JwtAuth>,
}

impl JwtHoop {
    pub fn new(auth: Arc<JwtAuth>) -> Self {
        Self { auth }
    }
}

#[async_trait]
impl Handler for JwtHoop {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        if self.auth.matches_except(req.uri().path()) {
            ctrl.call_next(req, depot, res).await;
            return;
        }
        let token = req
            .headers()
            .get(salvo::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(bearer_token);
        match self.auth.authenticate(token.as_deref()) {
            Ok(payload) => {
                depot.insert_typed(payload);
                ctrl.call_next(req, depot, res).await;
            }
            Err(e) => {
                // 与 axum/actix/rocket/poem 家族统一格式
                log::info!(
                    "JWT middleware rejected ({} {}): {e}",
                    req.method(),
                    req.uri().path()
                );
                res.status_code(StatusCode::UNAUTHORIZED);
                // 先钉 content-type：Json scribe 走 try_set_header（已存在则不覆写），
                // 否则会写成 application/json; charset=utf-8，破坏与其余适配层的响应头一致性。
                res.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                res.render(Json(unauthorized_body(&e)));
                // salvo 官方 MaxSizeHandler 惯例：渲染终止响应后显式截断后续 handler（本分支不 call_next，行为等价，防将来改动漏网）
                ctrl.skip_rest();
            }
        }
    }
}
