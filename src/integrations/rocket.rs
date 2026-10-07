// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! rocket integration (request guard + 401 catcher; rocket's idiomatic per-route auth).
//!
//! rocket 惯例是「按路由挂守卫」——需要公开的路由不挂 `JwtGuard` 即可（相当于 except 白名单：
//! 中间件式的 `middleware.except` 路径在 rocket 下请直接不挂守卫，挂上会被守卫以 500 显式拒绝并在 error 日志里说明原因）。
//!
//! **统一 401 JSON 体由 catcher 渲染**：rocket 0.5 的守卫失败只把 `Status` 交给 catcher——route codegen
//! 对 `Outcome::Error((status, err))` 是 `warn!(…); return Outcome::Error(status)`（见 rocket_codegen 0.5.1
//! `attribute/route/mod.rs` 的 `request_guard_decl`），`err` 仅用于 `{:?}` 日志、其 `Responder` 不会被调用。
//! 因此本适配层除守卫外还需注册 [`jwt_unauthorized`]：
//!
//! ```ignore
//! let app = rocket::build()
//!     .manage(std::sync::Arc::new(auth))
//!     .register("/", rocket::catchers![jwt_unauthorized])
//!     .mount("/", rocket::routes![me]);
//! ```
//!
//! 只挂守卫、不注册 catcher 时仍是 401，但响应体是 rocket 默认文案（非统一 JSON）。
//!
//! **注册范围**：`register("/", …)` 会接管**全应用**的 401——包括你自己路由 `return Status::Unauthorized`
//! 等非守卫来源（同样被改写成统一 JSON、走兜底文案 "Token authentication failed"）。若应用存在非 JWT 语义的
//! 401，请把 catcher 注册在受保护路由的公共前缀下（`.register("/api", …)`，catcher 按路径段前缀匹配），
//! 其余路径保持原样；自己的 401 catcher 也应挂更深路径。
//! **勿在相同 base 重复注册 401 catcher**：rocket 视「同状态码 + 同 base」为冲突，ignite 期报错拒绝启动。

use std::sync::{Arc, OnceLock};

use rocket::Response;
use rocket::http::{ContentType, Status};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::Responder;

use super::JwtAuth;
use crate::error::JwtError;
use crate::jwt::{JwtPayload, bearer_token};
use crate::native::unauthorized_body;

/// 请求守卫：`fn handler(p: JwtGuard)`。payload 经 `p.0` 读取。
pub struct JwtGuard(pub JwtPayload);

/// 本请求的拒绝原因：守卫写入（`local_cache` 只插入一次），[`jwt_unauthorized`] 读取。
fn reject_slot<'r>(req: &'r Request<'_>) -> &'r OnceLock<JwtError> {
    req.local_cache(OnceLock::new)
}

/// 统一 401 响应体（[`jwt_unauthorized`] 的返回类型；实现 `Responder` 即响应渲染器）
#[derive(Debug)]
pub struct JwtRejection {
    pub status: Status,
    pub body: serde_json::Value,
}

impl<'r> Responder<'r, 'static> for JwtRejection {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .status(self.status)
            .header(ContentType::JSON)
            .sized_body(None, std::io::Cursor::new(self.body.to_string()))
            .ok()
    }
}

/// 401 catcher：`rocket::build().register("/", rocket::catchers![jwt_unauthorized])`
#[rocket::catch(401)]
pub fn jwt_unauthorized(req: &Request<'_>) -> JwtRejection {
    let body = match reject_slot(req).get() {
        Some(e) => unauthorized_body(e),
        // 非本守卫产生的 401（app 自己的 catcher）不该走到这里；兜底用统一文案
        None => unauthorized_body(&JwtError::invalid("Token authentication failed")),
    };
    JwtRejection {
        status: Status::Unauthorized,
        body,
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for JwtGuard {
    type Error = JwtRejection;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(auth) = req.rocket().state::<Arc<JwtAuth>>() else {
            log::error!(
                "JwtGuard: `Arc<JwtAuth>` is not managed — add .manage(Arc::new(auth)) to the Rocket"
            );
            return Outcome::Error((
                Status::InternalServerError,
                JwtRejection {
                    status: Status::InternalServerError,
                    body: serde_json::json!({"code":500,"msg":"JwtAuth state not managed","data":null}),
                },
            ));
        };
        if auth.matches_except(req.uri().path().as_str()) {
            // rocket 无「跳过并放行」的守卫语义：except 路径请直接不挂守卫，挂上则显式报用法错误
            log::error!(
                "JwtGuard mounted on except path {} — do not mount the guard on except paths",
                req.uri().path()
            );
            return Outcome::Error((
                Status::InternalServerError,
                JwtRejection {
                    status: Status::InternalServerError,
                    body: serde_json::json!({"code":500,"msg":"except paths should not mount JwtGuard","data":null}),
                },
            ));
        }
        let token = req
            .headers()
            .get_one("Authorization")
            .and_then(bearer_token);
        match auth.authenticate(token.as_deref()) {
            Ok(p) => Outcome::Success(JwtGuard(p)),
            Err(e) => {
                log::info!(
                    "JWT guard rejected ({} {}): {e}",
                    req.method(),
                    req.uri().path()
                );
                // Status 送达 catcher；错误本体放请求本地缓存（rocket 丢弃 Error 值），
                // 这里仍带完整 JwtRejection 是为了日志可读、且万一日后 rocket 改用 Error 的 Responder 也语义正确。
                let body = unauthorized_body(&e);
                let _ = reject_slot(req).set(e);
                Outcome::Error((
                    Status::Unauthorized,
                    JwtRejection {
                        status: Status::Unauthorized,
                        body,
                    },
                ))
            }
        }
    }
}
