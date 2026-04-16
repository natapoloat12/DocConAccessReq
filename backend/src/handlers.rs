use axum::{
    extract::{Json, State, Query},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Extension,
};
use crate::models::{FirewallRequest, FirewallResponse};
use crate::auth::Claims;
use validator::Validate;
use tracing::{info, warn, error};
use regex::Regex;
use chrono::{NaiveDate, Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use std::env;

#[derive(Deserialize)]
pub struct CleanupQuery {
    #[serde(default)]
    dry_run: bool,
}

pub async fn cleanup_expired_handler(
    State(state): State<crate::routes::AppState>,
    headers: HeaderMap,
    Query(query): Query<CleanupQuery>,
) -> impl IntoResponse {
    // 1. API Key Authentication
    let api_key = env::var("CLEANUP_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        error!("CLEANUP_API_KEY not set in environment");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "System configuration error"})),
        ).into_response();
    }

    let provided_key = headers.get("X-API-KEY")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    if provided_key != api_key {
        warn!("Unauthorized cleanup attempt from {:?}", headers.get("x-forwarded-for"));
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Unauthorized"})),
        ).into_response();
    }

    let client = &state.fortigate;
    info!("Starting cleanup of expired policies (dry_run={})", query.dry_run);

    let mut checked = 0;
    let mut deleted = 0;
    let mut skipped = 0;
    let mut errors = Vec::new();

    let policies = match client.list_all_policies().await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to list policies: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "checked": 0,
                    "deleted": 0,
                    "skipped": 0,
                    "errors": [e]
                })),
            ).into_response();
        }
    };

    // 2. Strict Policy Filtering
    let date_regex = Regex::new(r"^AUTO-(?:T2S|E2S)-Doc-(\d{8})$").unwrap();
    let current_date = Utc::now().naive_utc().date();
    let grace_days = env::var("CLEANUP_GRACE_DAYS")
        .unwrap_or_else(|_| "2".to_string())
        .parse::<i64>()
        .unwrap_or(2);

    for policy in policies {
        checked += 1;
        let name = policy["name"].as_str().unwrap_or_default();
        let policy_id = policy["policyid"].as_i64().unwrap_or_default();

        // 3. Strict Pattern Match
        if let Some(caps) = date_regex.captures(name) {
            let date_str = &caps[1];
            
            // 4. Safety Guards (Length and Valid Date)
            if name.len() != 21 { // "AUTO-T2S-Doc-YYYYMMDD" is 21 chars
                warn!("Policy name {} matches regex but has invalid length", name);
                skipped += 1;
                continue;
            }

            match NaiveDate::parse_from_str(date_str, "%Y%m%d") {
                Ok(policy_date) => {
                    let expiry_date = policy_date + Duration::days(grace_days);
                    
                    if current_date > expiry_date {
                        // 5. Safe Deletion Logging
                        info!("Deleting expired policy: {} (ID: {}) | Expiration: {} | Current: {}", 
                            name, policy_id, expiry_date, current_date);

                        if query.dry_run {
                            info!("DRY RUN: Skip actual deletion for {}", name);
                            deleted += 1;
                        } else {
                            match client.delete_policy(policy_id).await {
                                Ok(_) => {
                                    info!("Successfully deleted policy {}", name);
                                    deleted += 1;
                                }
                                Err(e) => {
                                    error!("Failed to delete policy {}: {}", name, e);
                                    errors.push(format!("Failed to delete {}: {}", name, e));
                                }
                            }
                        }
                    } else {
                        info!("Policy {} skipped (not yet expired). Expiry: {}", name, expiry_date);
                        skipped += 1;
                    }
                }
                Err(e) => {
                    warn!("Failed to parse date from policy name {}: {}", name, e);
                    skipped += 1;
                }
            }
        } else {
            // Silently skip unrelated policies, but we can log at debug if needed
            skipped += 1;
        }
    }

    info!("Cleanup Summary: Checked={}, Deleted={}, Skipped={}, Errors={}", 
        checked, deleted, skipped, errors.len());

    (
        StatusCode::OK,
        Json(json!({
            "checked": checked,
            "deleted": deleted,
            "skipped": skipped,
            "errors": errors
        })),
    ).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_regex() {
        let regex = Regex::new(r"^AUTO-(?:T2S|E2S)-Doc-(\d{8})$").unwrap();
        
        // Valid names
        assert!(regex.is_match("AUTO-T2S-Doc-20260416"));
        assert!(regex.is_match("AUTO-E2S-Doc-20260416"));
        
        // Invalid names
        assert!(!regex.is_match("T2S-Doc-20260416"));
        assert!(!regex.is_match("AUTO-T2S-Doc-2026041"));
        assert!(!regex.is_match("AUTO-T2S-Doc-20260416X"));
        assert!(!regex.is_match("XAUTO-T2S-Doc-20260416"));
    }

    #[test]
    fn test_date_parsing_and_expiry() {
        let date_str = "20260416";
        let policy_date = NaiveDate::parse_from_str(date_str, "%Y%m%d").unwrap();
        let grace_days = 2;
        let expiry_date = policy_date + Duration::days(grace_days);
        
        // 2026-04-16 + 2 days = 2026-04-18
        assert_eq!(expiry_date.to_string(), "2026-04-18");
        
        let current_date_expired = NaiveDate::from_ymd_opt(2026, 4, 19).unwrap();
        assert!(current_date_expired > expiry_date);
        
        let current_date_not_expired = NaiveDate::from_ymd_opt(2026, 4, 18).unwrap();
        assert!(!(current_date_not_expired > expiry_date));
    }
}

pub async fn handle_firewall_request(
    State(state): State<crate::routes::AppState>,
    Extension(claims): Extension<Claims>,
    Json(mut payload): Json<FirewallRequest>,
) -> impl IntoResponse {
    let client = &state.fortigate;
    info!("Received firewall request from user: {} ({:?})", claims.sub, claims.email);

    // 1. Email Handling
    if payload.confirmation_email.is_none() {
        if let Some(user_email) = payload.email.take() {
            payload.confirmation_email = Some(user_email);
        } else if let Some(user_email) = claims.email {
            payload.confirmation_email = Some(user_email);
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(FirewallResponse {
                    status: "error".to_string(),
                    message: "Confirmation email is required but was not found in profile or request.".to_string(),
                }),
            ).into_response();
        }
    }

    let final_email = payload.confirmation_email.clone().unwrap();
    let cc_emails = payload.cc_emails.take();

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

    // 4. Call FortiGate API
    match client.create_request_v2(
        &normalized_entries, 
        &payload.expiry, 
        &final_email, 
        cc_emails,
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
