use ldap3::{LdapConnAsync, LdapConnSettings, SearchEntry, Scope};
use std::env;
use tracing::{info, warn};

pub struct LdapAuthResult {
    pub username: String,
    pub email: Option<String>,
    pub fullname: Option<String>,
    pub employee_id: Option<String>,
}

/// Sanitize LDAP input to prevent injection
fn sanitize_ldap_input(input: &str) -> String {
    input.replace('\\', "\\5c")
         .replace('*', "\\2a")
         .replace('(', "\\28")
         .replace(')', "\\29")
         .replace('\0', "\\00")
}

pub async fn authenticate_with_ldap(username: &str, password: &str) -> Result<LdapAuthResult, String> {
    let ldap_url = env::var("LDAP_URL").map_err(|_| "LDAP_URL not set")?;
    let ldap_domain = env::var("LDAP_DOMAIN").unwrap_or_else(|_| "kce.co.th".to_string());
    
    // 1. Clean the username: if user typed "KCE\user", just take "user"
    let clean_username = if let Some(pos) = username.find('\\') {
        &username[pos + 1..]
    } else {
        username
    };

    // 2. Construct UPN formats for BIND (Do NOT sanitize these)
    let upn_co_th = format!("{}@kce.co.th", clean_username);
    let upn_local = format!("{}@kce.local", clean_username);

    info!("LDAP: Attempting connection to {}", ldap_url);

    let settings = LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(5));

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &ldap_url)
        .await
        .map_err(|e| {
            warn!("LDAP connection failure: {}", e);
            "Authentication service unavailable".to_string()
        })?;

    ldap3::drive!(conn);

    // TRY 1: user@kce.co.th
    info!("LDAP: Trying bind: {}", upn_co_th);
    let mut bind_res = ldap.simple_bind(&upn_co_th, password).await;
    
    let mut authenticated = match bind_res {
        Ok(res) => res.success().is_ok(),
        _ => false
    };

    // TRY 2: user@kce.local (if first one fails)
    if !authenticated {
        info!("LDAP: co.th failed, trying: {}", upn_local);
        bind_res = ldap.simple_bind(&upn_local, password).await;
        authenticated = match bind_res {
            Ok(res) => res.success().is_ok(),
            _ => false
        };
    }

    if !authenticated {
        return Err("Invalid credentials".to_string());
    }

    info!("LDAP: Authentication successful for {}", clean_username);

    let mut user_email = None;
    let mut fullname = None;
    let mut employee_id = None;

    // Use cleaned AND sanitized username for searching
    let safe_username = sanitize_ldap_input(clean_username);
    
    // Broad search filter
    let search_filter = format!("(|(userPrincipalName={})(userPrincipalName={})(sAMAccountName={}))", 
        upn_co_th, upn_local, safe_username);
    
    let base_dn = "DC=kce,DC=co,DC=th"; // Default base

    let attrs = vec!["mail", "displayName", "employeeID"];

    // Try search in co.th base
    if let Ok(search_res) = ldap.search(base_dn, Scope::Subtree, &search_filter, attrs.clone()).await {
        if let Ok((results, _)) = search_res.success() {
            if !results.is_empty() {
                let entry = SearchEntry::construct(results[0].clone());
                user_email = entry.attrs.get("mail").and_then(|m| m.get(0).cloned());
                fullname = entry.attrs.get("displayName").and_then(|m| m.get(0).cloned());
                employee_id = entry.attrs.get("employeeID").and_then(|m| m.get(0).cloned());
            }
        }
    }

    // If still no email, try local base
    if user_email.is_none() {
        if let Ok(search_res) = ldap.search("DC=kce,DC=local", Scope::Subtree, &search_filter, attrs).await {
            if let Ok((results, _)) = search_res.success() {
                if !results.is_empty() {
                    let entry = SearchEntry::construct(results[0].clone());
                    user_email = entry.attrs.get("mail").and_then(|m| m.get(0).cloned());
                    fullname = entry.attrs.get("displayName").and_then(|m| m.get(0).cloned());
                    employee_id = entry.attrs.get("employeeID").and_then(|m| m.get(0).cloned());
                }
            }
        }
    }

    Ok(LdapAuthResult {
        username: clean_username.to_string(),
        email: user_email,
        fullname,
        employee_id,
    })
}
