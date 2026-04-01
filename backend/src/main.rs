mod models;
mod fortigate;
mod handlers;
mod routes;
mod ldap;
mod auth;
mod middleware;

use std::net::SocketAddr;
use std::sync::Arc;
use std::env;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crate::fortigate::FortiGateClient;
use crate::auth::LoginRateLimiter;
use crate::routes::AppState;
use dotenvy::dotenv;

#[tokio::main]
async fn main() {
    // 1. Initialize Logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 2. Load Environment Variables
    dotenv().ok();
    
    // 3. Initialize Shared State
    let state = AppState {
        fortigate: Arc::new(FortiGateClient::new()),
        limiter: Arc::new(LoginRateLimiter::new()),
    };

    // 4. CORS
    let allowed_origin = env::var("ALLOWED_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:8080".to_string())
        .parse::<axum::http::HeaderValue>()
        .unwrap();

    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_credentials(true);

    // 5. Build Router
    let app = routes::create_router(state).layer(cors);

    // 6. Start Server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Backend server starting on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
