use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use jsonwebtoken::{encode, EncodingKey, DecodingKey, Validation, decode, Header};
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Mutex;
use std::collections::HashMap;
use chrono::{Utc, Duration};
use tracing::{info, warn, error};
use crate::models::{LoginRequest, FirewallResponse};
use crate::ldap::authenticate_with_ldap;

pub const AUTH_COOKIE_NAME: &str = "jwt_auth";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: Option<String>,
    pub fullname: Option<String>,
    pub employee_id: Option<String>,
    pub exp: i64,
}

// ... (LoginRateLimiter remains unchanged)

pub async fn login_handler(
    State(state): State<crate::routes::AppState>,
    jar: CookieJar,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let limiter = &state.limiter;
    info!("Login attempt for user: {}", payload.username);

    // Rate Limiting
    if !limiter.check_limit(&payload.username) {
        warn!("Rate limit exceeded for user: {}", payload.username);
        return (StatusCode::TOO_MANY_REQUESTS, Json(FirewallResponse {
            status: "error".to_string(),
            message: "Too many login attempts. Please try again in 15 minutes.".to_string(),
        })).into_response();
    }

    match authenticate_with_ldap(&payload.username, &payload.password).await {
        Ok(user_info) => {
            let secret = env::var("JWT_SECRET").expect("CRITICAL: JWT_SECRET must be set for security");
            let exp = (Utc::now() + Duration::hours(8)).timestamp();
            
            let claims = Claims {
                sub: user_info.username,
                email: user_info.email,
                fullname: user_info.fullname,
                employee_id: user_info.employee_id,
                exp,
            };

            let token = match encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_ref()),
            ) {
                Ok(t) => t,
                Err(e) => {
                    error!("JWT Encoding Error: {}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(FirewallResponse {
                        status: "error".to_string(),
                        message: "Internal Session Error".to_string(),
                    })).into_response();
                }
            };

            let is_secure = env::var("COOKIE_SECURE").unwrap_or_else(|_| "true".to_string()) == "true";

            let cookie = Cookie::build((AUTH_COOKIE_NAME, token))
                .path("/")
                .http_only(true)
                .secure(is_secure)
                .same_site(SameSite::Lax)
                .build();

            info!("Login successful for user: {}, Secure: {}", claims.sub, is_secure);
            
            (jar.add(cookie), Json(FirewallResponse {
                status: "success".to_string(),
                message: "Logged in successfully".to_string(),
            })).into_response()
        }
        Err(e) => {
            warn!("Login failed: {}", e);
            (StatusCode::UNAUTHORIZED, Json(FirewallResponse {
                status: "error".to_string(),
                message: "Invalid username or password".to_string(), // Generic error
            })).into_response()
        }
    }
}

pub struct LoginRateLimiter {
    attempts: Mutex<HashMap<String, Vec<i64>>>,
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self { attempts: Mutex::new(HashMap::new()) }
    }

    pub fn check_limit(&self, username: &str) -> bool {
        let mut attempts = self.attempts.lock().unwrap();
        let now = Utc::now().timestamp();
        
        let user_attempts = attempts.entry(username.to_string()).or_insert(Vec::new());
        
        // Keep only attempts from the last 15 minutes
        user_attempts.retain(|&t| now - t < 15 * 60);
        
        if user_attempts.len() >= 5 {
            return false; // Too many attempts
        }
        
        user_attempts.push(now);
        true
    }
}

pub async fn logout_handler(jar: CookieJar) -> impl IntoResponse {
    let is_secure = env::var("COOKIE_SECURE").unwrap_or_else(|_| "true".to_string()) == "true";
    let cookie = Cookie::build((AUTH_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(is_secure)
        .max_age(cookie::time::Duration::seconds(0))
        .build();
    
    (jar.add(cookie), Json(FirewallResponse {
        status: "success".to_string(),
        message: "Logged out successfully".to_string(),
    }))
}

pub async fn verify_handler(
    Extension(claims): Extension<crate::auth::Claims>,
) -> impl IntoResponse {
    tracing::info!(">>> VERIFY_HANDLER: Sending claims for user: {}", claims.sub);
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::CACHE_CONTROL, "no-store, no-cache, must-revalidate".parse().unwrap());
    headers.insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());
    headers.insert(axum::http::header::EXPIRES, "0".parse().unwrap());
    (headers, Json(claims))
}

pub fn validate_jwt(token: &str) -> Result<Claims, String> {
    let secret = env::var("JWT_SECRET").expect("CRITICAL: JWT_SECRET must be set");
    
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|e| format!("JWT Validation failed: {}", e))
}
