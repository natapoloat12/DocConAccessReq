use axum::{
    extract::Request,
    middleware::Next,
    response::{Response},
    http::StatusCode,
};
use axum_extra::extract::cookie::CookieJar;
use tracing::{warn};
use crate::auth::{AUTH_COOKIE_NAME, validate_jwt};

pub async fn auth_middleware(
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();
    tracing::info!(">>> AUTH_MIDDLEWARE: Intercepted request for path: {}", path);
    
    let cookie = jar.get(AUTH_COOKIE_NAME);
    if cookie.is_none() {
        tracing::warn!(">>> AUTH_MIDDLEWARE: No cookie found for path: {}", path);
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    let cookie_val = cookie.unwrap().value().to_string();
    tracing::info!(">>> AUTH_MIDDLEWARE: Cookie found, validating JWT...");

    match validate_jwt(&cookie_val) {
        Ok(claims) => {
            tracing::info!(">>> AUTH_MIDDLEWARE: JWT Valid. User: {}", claims.sub);
            request.extensions_mut().insert(claims);
            Ok(next.run(request).await)
        }
        Err(e) => {
            tracing::warn!(">>> AUTH_MIDDLEWARE: JWT Invalid: {}. Redirecting...", e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
