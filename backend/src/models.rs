use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct FirewallRequest {
    #[validate(ip)]
    pub ip: Option<String>, // Legacy single IP
    
    pub name: Option<String>, // Legacy single Name
    
    pub entries: Option<Vec<FirewallEntry>>, // New multiple entries format
    
    #[validate(email)]
    pub email: Option<String>,
    
    pub expiry: String, 

    pub document_name: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct FirewallEntry {
    pub name: String,
    #[validate(ip)]
    pub ip: String,
}

#[derive(Serialize)]
pub struct FirewallResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}
