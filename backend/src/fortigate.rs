use reqwest::Client;
use serde_json::{json, Value};
use crate::models::FirewallRequest;
use std::env;
use chrono::{DateTime, Utc};
use tracing::{info, warn, error};

use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub struct FortiGateClient {
    base_url: String,
    api_token: String,
    client: Client,
}

fn escape_html(input: &str) -> String {
    input.replace('&', "&amp;")
         .replace('<', "&lt;")
         .replace('>', "&gt;")
         .replace('"', "&quot;")
         .replace('\'', "&#39;")
}

impl FortiGateClient {
    pub fn new() -> Self {
        let base_url = env::var("FORTIGATE_BASE_URL").expect("FORTIGATE_BASE_URL must be set");
        let api_token = env::var("FORTIGATE_API_TOKEN").expect("FORTIGATE_API_TOKEN must be set");
        let verify_ssl = env::var("FORTIGATE_VERIFY_SSL").unwrap_or_else(|_| "true".to_string()) == "true";
        
        let client = Client::builder()
            .danger_accept_invalid_certs(!verify_ssl)
            .use_rustls_tls()
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url,
            api_token,
            client,
        }
    }

    pub async fn create_request_v2(
        &self, 
        entries: &[crate::models::FirewallEntry], 
        expiry: &str, 
        user_email: &str, 
        document_name: Option<String>
    ) -> Result<(), String> {
        let expiry_dt = DateTime::parse_from_rfc3339(&format!("{}:00Z", expiry))
            .map_err(|e| format!("Invalid expiry date format: {}", e))?;
        let expiry_utc = expiry_dt.with_timezone(&Utc);
        
        let date_str = expiry_utc.format("%Y%m%d").to_string();
        let schedule_name = date_str.clone();
        let policy_name = format!("T2S-Doc-{}", date_str);
        
        info!("Processing multi-entry request for Policy: {}, Entries: {}, Doc: {:?}", policy_name, entries.len(), document_name);

        let mut addr_names = Vec::new();
        for entry in entries {
            let addr_name = self.ensure_address_object_v2(&entry.name, &entry.ip).await?;
            addr_names.push(addr_name);
        }

        self.ensure_schedule(&schedule_name, expiry_utc.timestamp()).await?;
        let existing_policy = self.find_policy_by_name(&policy_name).await?;

        if let Some(policy) = existing_policy {
            let policy_id = policy["policyid"].as_i64().ok_or("Missing policyid")?;
            let mut srcaddr = policy["srcaddr"].as_array().cloned().unwrap_or_default();
            
            let mut updated = false;
            for addr_name in addr_names {
                if !srcaddr.iter().any(|a| a["name"] == addr_name) {
                    srcaddr.push(json!({"name": addr_name}));
                    updated = true;
                }
            }

            if updated {
                self.update_policy_srcaddr(policy_id, srcaddr).await?;
                info!("Updated existing policy {} with new addresses", policy_name);
            } else {
                info!("All addresses already exist in policy {}", policy_name);
            }
        } else {
            // Create new policy with the first address
            let first_addr = &addr_names[0];
            let new_policy_id = self.create_new_policy(&policy_name, &schedule_name, first_addr).await?;
            
            // If there are more addresses, update the policy
            if addr_names.len() > 1 {
                let srcaddr: Vec<Value> = addr_names.iter().map(|name| json!({"name": name})).collect();
                self.update_policy_srcaddr(new_policy_id, srcaddr).await?;
            }

            info!("Created new policy {} (ID: {})", policy_name, new_policy_id);
            self.move_policy(new_policy_id, 285).await?;
        }

        self.send_notification_v2(entries, user_email, &expiry_utc, document_name).await;
        Ok(())
    }

    pub async fn create_request(&self, request: &FirewallRequest, user_email: &str) -> Result<(), String> {
        let entry = crate::models::FirewallEntry {
            name: request.name.clone().unwrap_or_else(|| format!("ADDR_{}", request.ip.as_ref().unwrap().replace('.', "_"))),
            ip: request.ip.clone().unwrap(),
        };
        self.create_request_v2(&[entry], &request.expiry, user_email, request.document_name.clone()).await
    }

    async fn send_notification_v2(
        &self, 
        entries: &[crate::models::FirewallEntry], 
        user_email: &str, 
        expiry: &DateTime<Utc>, 
        document_name: Option<String>
    ) {
        let smtp_host = env::var("SMTP_HOST").ok();
        let smtp_port = env::var("SMTP_PORT").ok().and_then(|p| p.parse::<u16>().ok());
        let smtp_user = env::var("SMTP_USER").ok();
        let smtp_pass = env::var("SMTP_PASS").ok();
        let smtp_cc = env::var("SMTP_CC").ok();
        let smtp_to = env::var("SMTP_TO").ok();

        info!("Email notification: From={} (User), To={:?}, CC={:?}, Host={:?}", user_email, smtp_to, smtp_cc, smtp_host);

        if let (Some(host), Some(port), Some(user), Some(pass)) = 
               (smtp_host, smtp_port, smtp_user, smtp_pass) {
            
            // 1. From: The Requester (Confirmation Email)
            let mut builder = Message::builder()
                .from(user_email.parse().expect("Invalid User Email as From"));

            // 2. To: Main Admin (SMTP_TO)
            if let Some(admin_to) = smtp_to {
                let trimmed = admin_to.trim();
                if !trimmed.is_empty() {
                    builder = builder.to(trimmed.parse().expect("Invalid SMTP_TO as To"));
                }
            }
            
            // 3. CC: Additional List (SMTP_CC) only
            if let Some(cc_list) = smtp_cc {
                info!("Found SMTP_CC list: {}", cc_list);
                let mut cc_count = 0;
                for email_addr in cc_list.split(',') {
                    let trimmed = email_addr.trim();
                    if !trimmed.is_empty() {
                        match trimmed.parse() {
                            Ok(mailbox) => { 
                                builder = builder.cc(mailbox); 
                                cc_count += 1;
                            },
                            Err(e) => error!("Invalid SMTP_CC email '{}': {}", trimmed, e),
                        }
                    }
                }
                info!("Added {} recipients to CC", cc_count);
            } else {
                warn!("SMTP_CC environment variable is NOT set or empty");
            }

            // HTML Table Generation
            let mut table_rows = String::new();
            let start_date = Utc::now().format("%Y-%m-%d %H:%M").to_string();
            let end_date = expiry.format("%Y-%m-%d %H:%M").to_string();

            for entry in entries {
                table_rows.push_str(&format!(
                    "<tr>\
                        <td style='border: 1px solid #ddd; padding: 8px; text-align: center;'>{}</td>\
                        <td style='border: 1px solid #ddd; padding: 8px; text-align: center;'>{}</td>\
                        <td style='border: 1px solid #ddd; padding: 8px; text-align: center;'>{}</td>\
                        <td style='border: 1px solid #ddd; padding: 8px; text-align: center;'>{}</td>\
                    </tr>",
                    escape_html(&entry.name), 
                    escape_html(&entry.ip), 
                    start_date, 
                    end_date
                ));
            }

            // Document List Generation
            let mut doc_list = String::new();
            if let Some(docs) = document_name {
                let mut count = 1;
                for doc in docs.split(',') {
                    let trimmed = doc.trim();
                    if !trimmed.is_empty() {
                        doc_list.push_str(&format!("{}. {}<br>", count, escape_html(trimmed)));
                        count += 1;
                    }
                }
            } else {
                doc_list = "N/A".to_string();
            }

            let email_html = format!(
                "<!DOCTYPE html><html><head><meta charset='UTF-8'></head>\
                <body style='font-family: sans-serif; line-height: 1.6; color: #333;'>\
                    <p>เรียน ผู้ที่เกี่ยวข้อง</p>\
                    <p>ขอแก้ไขไฟล์เอกสาร</p>\
                    <p><strong>ไฟล์เอกสารที่ต้องการแก้ไข:</strong><br>{}</p>\
                    <p><strong>รายละเอียดการเข้าใช้งาน:</strong></p>\
                    <table style='width: 100%; border-collapse: collapse; margin-top: 10px;'>\
                        <thead>\
                            <tr style='background-color: #f2f2f2;'>\
                                <th style='border: 1px solid #ddd; padding: 8px;'>Name</th>\
                                <th style='border: 1px solid #ddd; padding: 8px;'>IP Address</th>\
                                <th style='border: 1px solid #ddd; padding: 8px;'>ระยะเวลาเริ่ม</th>\
                                <th style='border: 1px solid #ddd; padding: 8px;'>ถึง</th>\
                            </tr>\
                        </thead>\
                        <tbody>{}</tbody>\
                    </table>\
                    <p style='margin-top: 20px; font-size: 0.9em; color: #777;'>\
                        Note: Access will be automatically revoked at the expiry time.<br>\
                        System: FortiGate Self-Service Portal\
                    </p>\
                </body></html>",
                doc_list, table_rows
            );

            let email = builder
                .subject("ขอแก้ไขไฟล์เอกสาร Document Control")
                .header(lettre::message::header::ContentType::TEXT_HTML)
                .body(email_html)
                .unwrap();

            let creds = Credentials::new(user, pass);
            let tls_params = TlsParameters::new(host.clone()).expect("Invalid TLS parameters");

            let mailer: AsyncSmtpTransport<Tokio1Executor> = if port == 465 {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
                    .unwrap()
                    .port(port)
                    .tls(Tls::Wrapper(tls_params))
                    .credentials(creds)
                    .build()
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
                    .unwrap()
                    .port(port)
                    .tls(Tls::Required(tls_params))
                    .credentials(creds)
                    .build()
            };

            match mailer.send(email).await {
                Ok(_) => info!("Email successfully queued for delivery to {}", user_email),
                Err(e) => error!("SMTP Error for {}: {:?}", user_email, e),
            }
        } else {
            warn!("SMTP configuration incomplete; cannot send email.");
        }
    }

    async fn send_notification(&self, ip: &str, user_email: &str, expiry: &DateTime<Utc>) {
        let entry = crate::models::FirewallEntry {
            name: "n/a".to_string(),
            ip: ip.to_string(),
        };
        self.send_notification_v2(&[entry], user_email, expiry, None).await;
    }

    async fn ensure_address_object_v2(&self, name: &str, ip: &str) -> Result<String, String> {
        // First check by name if it exists
        let name_url = format!("{}/api/v2/cmdb/firewall/address/{}", self.base_url, url_escape::encode_component(name));
        let res_name = self.client.get(&name_url)
            .bearer_auth(&self.api_token)
            .send()
            .await;

        if let Ok(response) = res_name {
            if response.status().is_success() {
                info!("Found existing address object by name: {}", name);
                return Ok(name.to_string());
            }
        }

        // If not found by name, check by IP (legacy behavior)
        let filter = format!("subnet=={} 255.255.255.255", ip);
        let search_url = format!("{}/api/v2/cmdb/firewall/address?filter={}", self.base_url, url_escape::encode_component(&filter));
        
        let res_ip = self.client.get(&search_url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| format!("Search address object failed: {}", e))?;

        if res_ip.status().is_success() {
            let json: Value = res_ip.json().await.map_err(|e| format!("Failed to parse search results: {}", e))?;
            if let Some(results) = json["results"].as_array() {
                if !results.is_empty() {
                    let existing_name = results[0]["name"].as_str().ok_or("Missing address name")?;
                    info!("Found existing address object '{}' for IP {}", existing_name, ip);
                    return Ok(existing_name.to_string());
                }
            }
        }

        // Not found by name or IP, create new one with provided name
        let create_url = format!("{}/api/v2/cmdb/firewall/address", self.base_url);
        let payload = json!({
            "name": name,
            "type": "ipmask",
            "subnet": format!("{}/32", ip),
            "comment": "Created via Self-Service Portal"
        });

        let response = self.client.post(&create_url)
            .bearer_auth(&self.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to create address: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let err_text = response.text().await.unwrap_or_default();
            if err_text.contains("already exists") || status.as_u16() == 424 {
                info!("Address object {} likely created in parallel", name);
                return Ok(name.to_string());
            }
            return Err(format!("FortiGate Error (Address): {}", err_text));
        }
        Ok(name.to_string())
    }

    async fn ensure_address_object(&self, ip: &str) -> Result<String, String> {
        let name = format!("ADDR_{}", ip.replace('.', "_"));
        self.ensure_address_object_v2(&name, ip).await
    }

    async fn ensure_schedule(&self, name: &str, end_utc: i64) -> Result<(), String> {
        let url = format!("{}/api/v2/cmdb/firewall.schedule/onetime/{}", self.base_url, name);
        let res = self.client.get(&url).bearer_auth(&self.api_token).send().await;

        if let Ok(response) = res {
            if response.status().is_success() {
                return Ok(());
            }
        }

        let create_url = format!("{}/api/v2/cmdb/firewall.schedule/onetime", self.base_url);
        let start_utc = Utc::now().timestamp();
        let payload = json!({
            "name": name,
            "start-utc": start_utc,
            "end-utc": end_utc,
            "color": 6
        });

        let response = self.client.post(&create_url)
            .bearer_auth(&self.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to create schedule: {}", e))?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            warn!("Schedule creation might have failed or already exists: {}", err);
        }
        Ok(())
    }

    async fn find_policy_by_name(&self, name: &str) -> Result<Option<Value>, String> {
        let url = format!("{}/api/v2/cmdb/firewall/policy?filter=name=={}", self.base_url, name);
        let response = self.client.get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| format!("Failed to find policy: {}", e))?;

        if response.status().is_success() {
            let json: Value = response.json().await.map_err(|e| e.to_string())?;
            if let Some(results) = json["results"].as_array() {
                if !results.is_empty() {
                    return Ok(Some(results[0].clone()));
                }
            }
        }
        Ok(None)
    }

    async fn create_new_policy(&self, name: &str, schedule: &str, addr_name: &str) -> Result<i64, String> {
        let url = format!("{}/api/v2/cmdb/firewall/policy", self.base_url);
        let payload = json!({
            "name": name,
            "action": "accept",
            "srcintf": [{"name": "Trust_Zone"}],
            "dstintf": [{"name": "Server_Zone"}],
            "srcaddr": [{"name": addr_name}],
            "dstaddr": [{"name": "S-Document_108"}],
            "service": [{"name": "RDP"}],
            "schedule": schedule,
            "nat": "disable",
            "status": "enable",
            "logtraffic": "all"
        });

        let response = self.client.post(&url)
            .bearer_auth(&self.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to create policy: {}", e))?;

        let json: Value = response.json().await.map_err(|e| e.to_string())?;
        json["mkey"].as_i64().ok_or_else(|| format!("Failed to get new policy ID: {:?}", json))
    }

    async fn update_policy_srcaddr(&self, policy_id: i64, srcaddr: Vec<Value>) -> Result<(), String> {
        let url = format!("{}/api/v2/cmdb/firewall/policy/{}", self.base_url, policy_id);
        let payload = json!({ "srcaddr": srcaddr });

        let response = self.client.put(&url)
            .bearer_auth(&self.api_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Failed to update policy: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("Update policy failed: {}", response.status()));
        }
        Ok(())
    }

    async fn move_policy(&self, policy_id: i64, before_id: i64) -> Result<(), String> {
        let url = format!("{}/api/v2/cmdb/firewall/policy/{}?action=move&before={}", self.base_url, policy_id, before_id);
        
        let response = self.client.put(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| format!("Failed to move policy: {}", e))?;

        if !response.status().is_success() {
            warn!("Policy move failed or restricted: {}", response.status());
        }
        Ok(())
    }
}
