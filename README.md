# Self-Service Firewall Access Request System

A production-ready portal for automating temporary RDP access requests on FortiGate firewalls.

## 🚀 Features
- **LDAP Integration:** Secure login using Active Directory credentials.
- **Automated Provisioning:** Creates FortiGate Address Objects and One-Time Schedules.
- **Smart Grouping:** Automatically groups daily requests into unified policies.
- **Safety First:** HTML-escaped email notifications and secure JWT session management.
- **Responsive UI:** Modern, mobile-friendly interface built with Tailwind CSS.

## 🛠 Tech Stack
- **Backend:** Rust (Axum, Tokio, Reqwest, Lettre)
- **Frontend:** Vanilla JavaScript, HTML5, Tailwind CSS
- **Infrastructure:** Docker, Nginx, Docker Compose

## 📦 Quick Start

1. **Configure Environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your FortiGate, LDAP, and SMTP credentials
   ```

2. **Launch with Docker:**
   ```bash
   docker-compose up -d --build
   ```

3. **Access:**
   - Frontend: `http://localhost:8080`
   - API: `http://localhost:3000`

## 🔒 Security Posture
- **JWT-only Auth:** State-less sessions using HttpOnly, Secure cookies.
- **Rate Limiting:** Protects against LDAP brute-force attempts.
- **Input Validation:** Strict server-side validation for IPs and Emails.
- **Sanitized Emails:** Protection against HTML injection in admin notifications.

## 📜 License
MIT
