// Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
#![cfg(feature = "ecat-grpc")]
use std::sync::Arc;

use jwt_rust::config::JwtConfig;
use jwt_rust::integrations::JwtAuth;
use jwt_rust::integrations::ecat::grpc::JwtInterceptor;
use tonic::service::Interceptor;

fn setup() -> (Arc<JwtAuth>, JwtInterceptor) {
    let auth = Arc::new(
        JwtAuth::from_config(JwtConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            ..Default::default()
        })
        .unwrap(),
    );
    (auth.clone(), JwtInterceptor::new(auth))
}

#[test]
fn missing_metadata_is_unauthenticated() {
    let (_, mut ic) = setup();
    let req = tonic::Request::new(());
    let status = ic.call(req).unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(status.message(), "Token not provided");
}

#[test]
fn valid_token_in_metadata_passes_and_injects_claims() {
    let (auth, mut ic) = setup();
    let token = auth
        .jwt()
        .encode(&serde_json::json!({"user_id": 7}), None)
        .unwrap();
    let mut req = tonic::Request::new(());
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let req = ic.call(req).unwrap();
    let claims = req.extensions().get::<jwt_rust::jwt::JwtPayload>().unwrap();
    assert_eq!(claims.get("user_id").unwrap(), 7);
}

#[test]
fn expired_token_is_unauthenticated_with_message() {
    let (_, mut ic) = setup();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // encode 产不出已过期令牌（exp 恒被覆写），故用同一密钥/算法直签
    let expired = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({"iss": "", "aud": "", "exp": n - 30, "nbf": n - 60, "iat": n - 60, "jti": "grpc-expired"}),
        &jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef"),
    )
    .unwrap();
    let mut req = tonic::Request::new(());
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {expired}").parse().unwrap(),
    );
    let status = ic.call(req).unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(status.message(), "Token has expired");
}

#[test]
fn interceptor_layer_mount_recipe_compiles_and_is_clone() {
    let (auth, _) = setup();
    use tower::Layer;
    let svc = tonic::service::InterceptorLayer::new(JwtInterceptor::new(auth)).layer(());
    fn assert_clone<T: Clone>(_: &T) {} // Routes::add_service 的 Clone 约束
    assert_clone(&svc);
}
