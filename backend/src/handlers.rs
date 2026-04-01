use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use crate::models::{FirewallRequest, FirewallResponse};
use crate::fortigate::FortiGateClient;
use crate::auth::Claims;
use validator::Validate;
use std::sync::Arc;
use tracing::{info, error, warn};

pub async fn handle_firewall_request(
    State(state): State<crate::routes::AppState>,
    Extension(claims): Extension<Claims>,
    Json(mut payload): Json<FirewallRequest>,
) -> impl IntoResponse {
    let client = &state.fortigate;
    info!("Received firewall request from user: {} ({:?})", claims.sub, claims.email);

    // 1. Email Handling
    if payload.email.is_none() {
        if let Some(user_email) = claims.email {
            payload.email = Some(user_email);
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(FirewallResponse {
                    status: "error".to_string(),
                    message: "Email address is required but was not found in profile or request.".to_string(),
                }),
            ).into_response();
        }
    }

    // 2. Backward Compatibility & Normalize Entries
    let mut normalized_entries = Vec::new();
    
    // Check if new "entries" field is provided
    if let Some(entries) = payload.entries.take() {
        normalized_entries = entries;
    } 
    // Otherwise, check for legacy single IP
    else if let Some(ip) = payload.ip.take() {
        normalized_entries.push(crate::models::FirewallEntry {
            name: payload.name.take().unwrap_or_else(|| format!("ADDR_{}", ip.replace('.', "_"))),
            ip,
        });
    }

    if normalized_entries.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(FirewallResponse {
                status: "error".to_string(),
                message: "No IP addresses or entries provided.".to_string(),
            }),
        ).into_response();
    }

    // 3. Validation & Duplicate Check
    let mut seen_ips = std::collections::HashSet::new();
    for entry in &normalized_entries {
        if let Err(e) = entry.validate() {
            return (
                StatusCode::BAD_REQUEST,
                Json(FirewallResponse {
                    status: "error".to_string(),
                    message: format!("Invalid entry ({}): {}", entry.ip, e),
                }),
            ).into_response();
        }
        if !seen_ips.insert(entry.ip.clone()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(FirewallResponse {
                    status: "error".to_string(),
                    message: format!("Duplicate IP address detected: {}", entry.ip),
                }),
            ).into_response();
        }
        if entry.name.trim().is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(FirewallResponse {
                    status: "error".to_string(),
                    message: format!("Name cannot be empty for IP: {}", entry.ip),
                }),
            ).into_response();
        }
    }

    // Also validate the main payload (expiry and email)
    if let Err(e) = payload.validate() {
        error!("Payload validation error: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(FirewallResponse {
                status: "error".to_string(),
                message: format!("Invalid input: {}", e),
            }),
        ).into_response();
    }

    let final_email = payload.email.clone().unwrap();

    // 4. Call FortiGate API
    match client.create_request_v2(
        &normalized_entries, 
        &payload.expiry, 
        &final_email, 
        payload.document_name
    ).await {
        Ok(_) => {
            (
                StatusCode::OK,
                Json(FirewallResponse {
                    status: "success".to_string(),
                    message: "Policy updated successfully with all entries".to_string(),
                }),
            ).into_response()
        }
        Err(e) => {
            error!("FortiGate client error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FirewallResponse {
                    status: "error".to_string(),
                    message: format!("Internal system error: {}", e),
                }),
            ).into_response()
        }
    }
}
