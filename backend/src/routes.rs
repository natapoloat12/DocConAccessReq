use axum::{
    routing::{post, get},
    Router,
    middleware,
};
use crate::handlers::handle_firewall_request;
use crate::auth::{login_handler, logout_handler, verify_handler, LoginRateLimiter};
use crate::middleware::auth_middleware;
use crate::fortigate::FortiGateClient;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub fortigate: Arc<FortiGateClient>,
    pub limiter: Arc<LoginRateLimiter>,
}

pub fn create_router(state: AppState) -> Router {
    // 1. Protected Routes
    let protected_routes = Router::new()
        .route("/api/firewall/request", post(handle_firewall_request))
        .route("/api/verify", get(verify_handler))
        .layer(middleware::from_fn(auth_middleware));

    // 2. Public Routes
    Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .merge(protected_routes)
        .with_state(state)
}
