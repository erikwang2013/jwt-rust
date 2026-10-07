// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
// jwt-rust - JWT authentication for Rust web frameworks
//! Framework-agnostic JWT authentication: one core, nine integrations, four storages.

pub mod config;
pub mod error;
pub mod factory;
pub mod jwt;
pub mod mascot;
pub mod middleware_support;
pub mod native;
pub mod storage;

#[cfg(any(
    feature = "axum",
    feature = "actix",
    feature = "rocket",
    feature = "poem",
    feature = "salvo",
    feature = "warp",
    feature = "bee-rust",
    feature = "ecat"
))]
pub mod integrations;

pub use error::JwtError;
pub use jwt::{Jwt, JwtPayload, bearer_token};
