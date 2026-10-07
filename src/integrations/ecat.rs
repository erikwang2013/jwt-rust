// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
//! e-cat 适配：复用 axum 适配套件（e-cat HTTP transport 即 axum，与 ecat-middleware/ecat-auth 同为 tower Layer 生态）。
//!
//! 与 `ecat-auth::JwtAuthLayer` 的关系：后者管基础鉴权（签名/iss/aud/claims），无黑名单、无刷新、无存储；
//! 本层走 jwt-rust 完整内核（校验 + 黑名单查询 + 拒绝刷新令牌当访问令牌）——二者可共存，按需选用。
//!
//! HTTP 层用法与 `integrations::axum` 完全相同（同一对类型）：`router.layer(JwtLayer::new(Arc::new(auth)))`。
//! gRPC 层（feature `ecat-grpc`）用 `grpc::JwtInterceptor`：`InterceptorLayer::new(JwtInterceptor::new(auth)).layer(svc)` 后交 `Routes::add_service`。
//! 挂载进 e-cat 应用时同样适用 ecat-middleware 的 layer 链顺序约定。

#[cfg(feature = "ecat-grpc")]
pub mod grpc;

pub use super::axum::{JwtLayer, JwtService};
