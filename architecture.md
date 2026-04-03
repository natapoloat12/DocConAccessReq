# 🏗️ System Architecture: Firewall Access Portal

This document provides a detailed technical explanation of the **Self-Service Firewall Access Request System**.

---

## 1. High-Level Overview

The system is a **Stateless API Orchestrator**. It does not maintain its own database; instead, it uses the **FortiGate Firewall** as the "Source of Truth" for all access states and the **LDAP Server** for identity management.

### Architecture Diagram
```mermaid
graph LR
    User((User)) <--> Nginx[Nginx Reverse Proxy]
    Nginx <--> Frontend[Vanilla JS Frontend]
    Nginx <--> Backend[Rust Axum Backend]
    
    subgraph "External Services"
        Backend <--> LDAP[LDAP/AD Server]
        Backend <--> FortiGate[FortiGate REST API]
        Backend <--> SMTP[SMTP Server]
    end
```

---

## 2. Component Breakdown

### A. Frontend (Presentation Layer)
- **Technology:** Vanilla HTML5, JavaScript (ES6+), Tailwind CSS (CDN).
- **Responsibility:** 
    - Collecting user input (IPs, Document Name, Expiry).
    - Client-side validation (Regex for IPs).
    - Managing session state via JWT cookies.
- **Communication:** Communicates exclusively with the Nginx proxy via the `/api` prefix.

### B. Backend (Logic Layer)
- **Framework:** [Axum](https://github.com/tokio-rs/axum) (Rust) running on the [Tokio](https://tokio.rs/) runtime.
- **Core Modules:**
    - `auth.rs`: Handles LDAP binding and JWT generation.
    - `fortigate.rs`: The "Orchestrator" that translates business logic into FortiGate API calls.
    - `handlers.rs`: Manages HTTP request/response cycles and input validation.
    - `middleware.rs`: Intercepts every request to verify the JWT in the cookie.

### C. Infrastructure (Deployment Layer)
- **Docker Compose:** Orchestrates two containers: `backend` and `frontend`.
- **Nginx:** Functions as a **Reverse Proxy**. It serves static files for the frontend and routes all traffic starting with `/api/` to the Rust backend on port 5050.

---

## 3. Data Flow: The Journey of a Request

When a user submits a request, the following sequence occurs:

1.  **Authentication Check:** The `auth_middleware` extracts the JWT from the `http-only` cookie. If valid, the request proceeds.
2.  **Validation:** The backend validates the IP addresses and expiry date using the `validator` crate.
3.  **FortiGate Orchestration (The "Triple Check"):**
    - **Step 1 (Address):** Checks if an address object for the IP exists. If not, it creates `ADDR_1.2.3.4`.
    - **Step 2 (Schedule):** Checks if a one-time schedule for the requested date exists (e.g., `20260401`). If not, it creates it.
    - **Step 3 (Policy):** It looks for a policy named `T2S-Doc-[Date]`. 
        - If it exists, it **appends** the new IP to the `srcaddr` list.
        - If not, it creates a **new policy** and uses `move` to place it before **Rule ID 285** (ensuring it bypasses the "Block All" rule).
4.  **Notification:** Once the firewall confirms success, the backend sends an email via SMTP.

---

## 4. Security Implementation

### Identity & Session
- **LDAP Binding:** No passwords are saved. The app performs a "Simple Bind" against your LDAP/AD. If successful, it discards the password and issues a JWT.
- **JWT (JSON Web Token):** Encrypted with a `JWT_SECRET`. Contains user info (email, name) and an 8-hour expiration.
- **HTTP-Only Cookies:** The JWT is stored in a cookie that cannot be accessed by JavaScript (XSS Protection).

### Network Security
- **Rate Limiting:** The `LoginRateLimiter` prevents brute-force attacks by limiting login attempts to 5 per 15 minutes per username.
- **CORS:** The backend only accepts requests from the `ALLOWED_ORIGIN` specified in the `.env` file.
- **TLS/SSL:** In production, Nginx Proxy Manager (NPM) terminates SSL, ensuring all traffic between the user and the server is encrypted.

---

## 5. Technical Decisions & Trade-offs

| Decision | Reason |
| :--- | :--- |
| **Rust (Axum)** | Chosen for extreme memory safety and performance. As a security tool, using a language that prevents memory leaks and crashes is critical. |
| **Statelessness** | By not having a database, the app is highly portable and never goes "out of sync" with the firewall. If a rule is deleted manually on the firewall, the app detects it on the next run. |
| **Nginx Proxy** | Decoupling the frontend from the backend allows for easy scaling and simplifies the handling of static assets and API routing. |
| **Rule ID 285** | Hardcoding the insertion point ensures that automated rules never interfere with critical system-wide "Top" rules or get "shadowed" by "Bottom" block rules. |

---

## 6. Environment Configuration

The architecture is controlled by the `.env` file:
- `FORTIGATE_BASE_URL`: API Endpoint for the firewall.
- `COOKIE_SECURE`: Toggle for HTTP vs HTTPS environments.
- `PORT`: The internal binding port (5050).
- `JWT_SECRET`: The key used to sign session tokens.
