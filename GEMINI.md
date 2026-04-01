# GEMINI.md - Self-Service Firewall Access Request System

## Project Overview
This project is a self-service portal designed to automate temporary firewall access requests (specifically for **RDP**) on a FortiGate firewall. Users submit their IP address, email, and a desired expiry date, and the system automatically creates or updates the necessary address objects, one-time schedules, and firewall policies on the FortiGate device.

### Architecture & Technologies
- **Backend (Rust):**
  - **Framework:** [Axum](https://github.com/tokio-rs/axum) with [Tokio](https://tokio.rs/) for asynchronous execution.
  - **API Client:** [Reqwest](https://docs.rs/reqwest/) for interacting with the FortiGate REST API.
  - **Validation:** [Validator](https://docs.rs/validator/) crate for server-side IP and email validation.
  - **Email:** [Lettre](https://lettre.at/) for SMTP notifications.
  - **Logging:** [Tracing](https://tracing.rs/) for structured logging.
- **Frontend (Vanilla HTML/JS):**
  - **Styling:** [Tailwind CSS](https://tailwindcss.com/) (loaded via CDN).
  - **Logic:** Vanilla JavaScript using the Fetch API.
  - **Validation:** Client-side regex for immediate feedback.
- **Infrastructure:**
  - **Docker:** `docker-compose` for orchestrating the backend and an Nginx-based frontend.
  - **Nginx:** Used as a reverse proxy for the frontend to route `/api` requests to the backend.

## Building and Running

### 1. Using Docker (Recommended)
Ensure you have `docker-compose` installed and your `.env` file configured in the root or specified in the `docker-compose.yml`.

```powershell
docker-compose up -d
```
- **Frontend:** `http://localhost:8080`
- **Backend API:** `http://localhost:3000`

### 2. Local Development (Manual)

#### Backend
1. Navigate to `backend/`.
2. Create/edit `.env` based on `.env.example`:
   ```env
   FORTIGATE_BASE_URL=https://your-fortigate-ip
   FORTIGATE_API_TOKEN=your-token
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your-email@gmail.com
   SMTP_PASS=your-app-password
   SMTP_FROM=your-email@gmail.com
   SMTP_TO=admin@example.com
   ```
3. Run the server:
   ```powershell
   cargo run
   ```

#### Frontend
1. Open `frontend/index.html` in a browser.
2. *Note:* If running the backend locally on port 3000 and the frontend via a simple file path, CORS is enabled in the backend to allow requests. However, the production-like setup uses Nginx to proxy `/api`.

## Project Structure & Key Files

### Core Backend Logic
- `backend/src/main.rs`: Server entry point, CORS, and logging initialization.
- `backend/src/fortigate.rs`: **Crucial Integration Logic.**
  - `ensure_address_object`: Checks for existing objects by subnet or creates new `ADDR_x_x_x_x` objects.
  - `ensure_schedule`: Creates one-time schedules named by date (YYYYMMDD).
  - `create_request`: Orchestrates the creation/update of policies, grouping requests by date into `T2S-Doc-YYYYMMDD` policies and moving them before rule ID **285**.
  - `send_notification`: Handles SMTP email delivery.
- `backend/src/handlers.rs`: Axum request handlers and payload validation.
- `backend/src/models.rs`: Structs for `FirewallRequest` and `FirewallResponse` with validation rules.

### Root Scripts (Exploratory/Testing)
The root directory contains several JavaScript files (e.g., `test_new_flow.js`, `real_backend.js`, `clone_policy.js`) which appear to be experimental scripts or earlier iterations used to test the FortiGate API logic before it was implemented in Rust. These are useful for debugging specific API interactions.

## Development Conventions

- **Security:** API tokens must never be exposed to the frontend. All FortiGate interactions happen server-side.
- **Validation:** All user inputs (IP, Email) must be validated on both the client and server.
- **Error Handling:** Backend failures (e.g., FortiGate API errors) should return meaningful JSON responses to the frontend.
- **Policy Management:** 
  - New policies are moved before a specific rule ID (default: 285) to ensure they take precedence over general blocking rules.
  - Requests for the same day are merged into a single policy by adding multiple source addresses.
- **Logging:** Use `tracing::info`, `warn`, and `error` for all significant events and errors.
