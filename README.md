# Synclo Backend

[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat&logo=redis&logoColor=white)](https://redis.io/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/zyr-ux/Synclo-Backend/docker-publish.yml?style=flat)](https://github.com/zyr-ux/Synclo-Backend/actions/workflows/docker-publish.yml)

**Synclo** is a secure, cross-platform clipboard manager that keeps your clipboard seamlessly in sync across your devices (Desktop, Mobile, Web).

This repository contains the **Synclo Backend**—the server that powers real-time synchronization, device management, and background push notifications for the Synclo client apps.

Built on a **Zero-Knowledge Architecture**, the backend acts strictly as an encrypted mediator: all encryption and decryption happen directly on your client devices. The server never learns your passwords, encryption keys, or the plaintext contents of your clipboard.

---

## 🚀 Key Features

*   🔒 **Zero-Knowledge Security:** Plaintext passwords, Master Keys, and decrypted clipboard entries never touch the server. All payloads are AES-encrypted before transmission.
*   ⚡ **Real-Time Push Synchronization:** Employs WebSockets for instant propagation of clipboard updates across client devices.
*   📲 **Mobile Background Push Notifications:** Integrated with UnifiedPush / FCM distributors for energy-efficient silent background wake-ups on Android devices.
*   🌐 **Multi-Instance Scalability:** Uses Redis Pub/Sub underneath to distribute WebSocket broadcasts, enabling the backend to scale across multiple server nodes.
*   🔄 **Smart Delta Synchronization:** Employs a soft-delete (tombstone) strategy to support robust synchronization for devices transitioning between offline and online states.
*   📌 **Granular Pin Management:** Lightweight dedicated pinning system ensuring pinned clipboard items are preserved during bulk history purges and immune to auto-pruning.
*   📊 **Age-Based Clipboard Retention & Auto-Pruning:** Server-wide configurable retention lifecycle (`CLIPBOARD_RETENTION_DAYS`) with automatic tombstone pruning for older unpinned entries while preserving pinned items.
*   🔒 **HTTPS & Transport Security:** Strict HTTPS/WSS enforcement mode (`HTTPS_ONLY`) with automatic HTTP-to-HTTPS redirection, HSTS headers, reverse proxy support (`X-Forwarded-Proto`), and loopback development exemptions.
*   📈 **Observability & Prometheus Telemetry:** Exposes anonymized, privacy-preserving operational metrics at `/metrics`.
*   🛡️ **Advanced Session Security:** Uses Refresh Token Rotation, token reuse detection, and global rate limiting to protect against session theft and brute-force attacks.
*   🔐 **Zero-Knowledge User Observability Design:** Structural email-less design where public ingress points (`/register`, `/auth/salt`) provide immediate, honest client feedback bounded by Redis rate limiters, while internal auth and recovery endpoints return uniform error responses (`401`) to prevent side-channel disclosures.

---

## 🌍 Default Server & Client Connection

A default, publicly hosted Synclo server instance is maintained for general use and comes **pre-configured out of the box** in the official Synclo client applications:

*   🌐 **Default API Base URL:** `https://synclo.zyrux.dev/api/v1`
*   📖 **Interactive API Documentation (ReDoc):** `https://synclo.zyrux.dev/api/docs`
*   ⚡ **WebSocket Sync Endpoint:** `wss://synclo.zyrux.dev/ws/v1/sync`

Thanks to Synclo's **Zero-Knowledge Architecture**, all clipboard payloads are encrypted client-side using your local keys before transmission—the hosted server cannot decrypt or inspect your passwords, keys, or clipboard contents.

### Using a Custom Self-Hosted Server

If you prefer complete data sovereignty by self-hosting this backend, you can easily switch servers in the Synclo client apps:
1. Deploy your server instance using the [Quick Start](#quick-start) instructions below.
2. In the Synclo client app, navigate to **Settings** → **Server URL**
3. Switch from the default server and enter your custom self-hosted domain (e.g., `https://synclo.yourdomain.com`).

---

<a id="quick-start" name="quick-start"></a>

## ⚙️ Quick Start

### 🔧 Configuration & Secrets

Before deploying Synclo, generate your secret keys and review the available configuration parameters.

#### Generate Secret Keys
Generate two random 32-byte hexadecimal keys for `SECRET_KEY` and `REFRESH_TOKEN_HASH_KEY`:
```bash
openssl rand -hex 32
```
Run it twice (once for each key) and insert the generated values into your configuration.

#### Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SECRET_KEY` | *(Required)* | Secret key used for signing JWT access tokens (minimum 32 characters). |
| `REFRESH_TOKEN_HASH_KEY` | *(Required)* | Secret key used for HMAC hashing of refresh tokens (minimum 16 characters). |
| `ALGORITHM` | `HS256` | JWT signing algorithm (`HS256`, `HS384`, or `HS512`). |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | JWT access token expiration time in minutes. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `30` | Refresh token lifespan in days before re-authentication is required. |
| `DATABASE_URL` | `sqlite:///./data/synclo.db` | SQLAlchemy database connection string (`sqlite:////app/data/synclo.db` in container setups). |
| `REDIS_URL` | `redis://redis:6379` | Redis connection string for WebSocket pub/sub broadcasting and rate limiting. Production Compose uses authenticated Redis. |
| `REDIS_PASSWORD` | *(Required in Compose)* | Password for the production Compose Redis service. Use a strong random value. |
| `HTTPS_ONLY` | `false` | Enforces strict HTTPS redirection (`307`), HSTS headers, and secure WebSockets (`WSS`). Defaults to `false` if omitted. |
| `ENVIRONMENT` | `development` | Deployment environment (`development` or `production`). Production enforces strict push endpoint security constraints. |
| `ALLOW_ARBITRARY_PUSH_ENDPOINTS` | `false` | Allows UnifiedPush subscriptions to non-whitelisted domains. Strictly forbidden in production. |
| `ALLOW_LOCAL_PUSH_ENDPOINTS` | `false` | Allows UnifiedPush subscriptions to local/private IP addresses and loopback. Strictly forbidden in production. |
| `PUSH_PROVIDERS_FILE` | `app/utilities/push_providers.json` | Path to the JSON file listing trusted UnifiedPush provider domains. |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Comma-separated list of trusted upstream reverse proxy IP addresses. |
| `CLIPBOARD_RETENTION_DAYS` | `30` | Auto-pruning retention lifecycle in days for unpinned clipboard items (`0` to disable). Pinned items are immune. |
| `TOMBSTONE_RETENTION_DAYS` | `30` | Retention duration in days for deletion records (tombstones) enabling offline client synchronization. |
| `BACKUP_ENCRYPTION_KEY` | `None` *(unset)* | Optional Fernet key used by operational backup utilities (`backup_db.py`) to encrypt SQLite database snapshots (`.db.enc`). |
| `BACKUP_RETENTION_DAYS` | `30` | Retention duration in days for database backup snapshots before automatic pruning. |
| `BACKUP_DIR` | `data/backups` | Directory path where SQLite database backups are stored. |
| `SYNCLO_DOMAIN` | `synclo.yourdomain.com` | Public domain name used by Caddy in Docker Compose for automatic Let's Encrypt / ZeroSSL certificates. |

---

### 🚀 Deployment Options

Synclo can be deployed in production with automatic HTTPS or run locally for development. Choose the setup that matches your environment:

*   **[Method 1: All-in-One Docker Stack (Recommended)](#method-1-all-in-one-docker-stack-with-caddy-recommended):** Production-ready, single-file `compose.yaml` with automatic SSL/TLS via embedded Caddy.
*   **[Method 2: Standalone Docker (Behind Host Reverse Proxy)](#method-2-standalone-docker-behind-host-reverse-proxy):** Run Synclo and Redis in Docker while using an existing Caddy, Nginx, or Traefik service on the host.
*   **[Method 3: Local Development (from Source)](#method-3-local-development-from-source):** For contributors developing and testing locally.

---

#### Method 1: All-in-One Docker Stack with Caddy (Recommended)

This is the recommended production deployment. It runs **Synclo Backend**, **Redis**, and **Caddy** together using a single, self-contained `compose.yaml` file. Caddy's configuration is embedded directly using Docker Compose `configs`—no separate configuration files on disk are needed.

**1. Create `compose.yaml`:**
Save the following as `compose.yaml` on your server, replacing `synclo.yourdomain.com` with your public domain and inserting your generated secret keys:

```yaml
services:
  synclo-backend:
    image: ghcr.io/zyr-ux/synclo-backend:latest
    restart: unless-stopped
    expose:
      - "8000"
    environment:
      SECRET_KEY: "change_this_to_a_random_hex_key"
      REFRESH_TOKEN_HASH_KEY: "change_this_to_a_random_hex_key"
      DATABASE_URL: "sqlite:////app/data/synclo.db"
      REDIS_URL: "redis://:${REDIS_PASSWORD}@redis:6379/0"
      REDIS_PASSWORD: "change_this_to_a_strong_random_password"
      HTTPS_ONLY: "true"
      CLIPBOARD_RETENTION_DAYS: "30"
      TOMBSTONE_RETENTION_DAYS: "30"
    user: "10001:10001"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=5)"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 10s

  redis:
    image: redis:7-alpine
    container_name: redis
    restart: unless-stopped
    environment:
      REDIS_PASSWORD: "${REDIS_PASSWORD}"
    command:
      - redis-server
      - --requirepass
      - "${REDIS_PASSWORD}"
      - --maxmemory
      - 256mb
      - --maxmemory-policy
      - noeviction
    expose:
      - 6379
    healthcheck:
      test: ["CMD-SHELL", "redis-cli --no-auth-warning -a \"$$REDIS_PASSWORD\" ping | grep PONG"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 5s

  caddy:
    image: caddy:2-alpine
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    environment:
      SYNCLO_DOMAIN: "synclo.yourdomain.com" # Change this
    configs:
      - source: caddyfile
        target: /etc/caddy/Caddyfile
    volumes:
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      synclo-backend:
        condition: service_healthy

configs:
  caddyfile:
    content: |
      {$SYNCLO_DOMAIN} {
          encode gzip zstd

          @backend {
              path /api/* /ws/*
          }

          handle @backend {
              reverse_proxy synclo-backend:8000 {
                  header_up Host {host}
                  header_up X-Real-IP {remote_host}
                  header_up X-Forwarded-For {remote_host}
                  header_up X-Forwarded-Proto {scheme}
              }
          }

          handle {
              error "Not Found" 404
          }
      }

volumes:
  caddy_data:
  caddy_config:
```

**2. Start the Stack:**
```bash
docker compose up -d
```
The stack will start and Caddy will automatically provision TLS certificates for your domain. You can monitor the logs with:
```bash
docker compose logs -f
```

Once running, you can explore the interactive API documentation (ReDoc) at `https://<your-domain>/api/docs`.

---

#### Method 2: Standalone Docker (Behind Host Reverse Proxy)

Use this method if you already run a reverse proxy (such as Caddy or Nginx) directly on your host OS.

**1. Create `compose.yaml`:**
Run the backend and Redis container stack:

```yaml
services:
  synclo-backend:
    image: ghcr.io/zyr-ux/synclo-backend:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      SECRET_KEY: "change_this_to_a_random_hex_key"
      REFRESH_TOKEN_HASH_KEY: "change_this_to_a_random_hex_key"
      DATABASE_URL: "sqlite:////app/data/synclo.db"
      REDIS_URL: "redis://:${REDIS_PASSWORD}@redis:6379/0"
      REDIS_PASSWORD: "change_this_to_a_strong_random_password"
      HTTPS_ONLY: "true"
      CLIPBOARD_RETENTION_DAYS: "30"
      TOMBSTONE_RETENTION_DAYS: "30"
    user: "10001:10001"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=5)"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 10s

  redis:
    image: redis:7-alpine
    container_name: redis
    restart: unless-stopped
    environment:
      REDIS_PASSWORD: "${REDIS_PASSWORD}"
    command:
      - redis-server
      - --requirepass
      - "${REDIS_PASSWORD}"
      - --maxmemory
      - 256mb
      - --maxmemory-policy
      - noeviction
    expose:
      - 6379
    healthcheck:
      test: ["CMD-SHELL", "redis-cli --no-auth-warning -a \"$$REDIS_PASSWORD\" ping | grep PONG"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 5s

Start the containers:
```bash
docker compose up -d
```

**2. Configure Host Reverse Proxy (Caddy Example):**
Add the following block to your host's `/etc/caddy/Caddyfile`, replacing `synclo.yourdomain.com` with your domain:

```caddyfile
synclo.yourdomain.com {
    encode gzip zstd

    @backend {
        path /api/* /ws/*
    }

    handle @backend {
        reverse_proxy localhost:8000 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    handle {
        error "Not Found" 404
    }
}
```

Reload Caddy to apply changes:
```bash
sudo systemctl reload caddy
```

---

## 🛠️ Operational Utilities

The `app/utilities/` folder provides administrative tools and helper routines for database maintenance and disaster recovery:

### 1. Database Backups (`app/utilities/backup_db.py`)
Performs transaction-safe online SQLite backups with integrity verification, optional Fernet encryption, and automatic retention pruning:
```bash
# Create standard .db snapshot:
python app/utilities/backup_db.py

# Create encrypted .db.enc snapshot (recommended for defense-in-depth against metadata exposure):
python app/utilities/backup_db.py --key "<fernet-key>"

# Dry-run test restoration into a sandboxed temporary directory:
python app/utilities/backup_db.py --verify-restore data/backups/synclo_backup_YYYYMMDD_HHMMSS.db.enc --key "<fernet-key>"

# Restore backup to active database:
python app/utilities/backup_db.py --restore data/backups/synclo_backup_YYYYMMDD_HHMMSS.db.enc --key "<fernet-key>"
```

### 2. Manual Backup Decryption (`app/utilities/decrypt_db.py`)
Dedicated, standalone CLI utility allowing administrators to decrypt any `.db.enc` backup file into a standard SQLite `.db` database without running the backend:
```bash
python app/utilities/decrypt_db.py data/backups/synclo_backup_YYYYMMDD_HHMMSS.db.enc --output restored.db --key "<fernet-key>"
```

### 3. Push Distributor Domain Allowlist (`app/utilities/push_providers.json`)
Lists trusted UnifiedPush provider domains (`ntfy.sh`, `push.nextcloud.com`, `up.kde.org`, `unifiedpush.org`). You can add custom self-hosted distributor domains by updating this file or mounting a custom JSON file.


---

#### Method 3: Local Development (from Source)

For contributors and developers running Synclo locally from source:

**Option A: Docker Compose (Local Build)**
1. **Clone & Configure:**
   ```bash
   git clone https://github.com/zyr-ux/Synclo-Backend.git
   cd Synclo-Backend
   cp .env.example .env
   ```
2. **Build and Run:**
   ```bash
   docker compose up -d --build
   ```

**Option B: Manual Setup (Python Virtual Environment)**
1. **Clone & Configure:**
   ```bash
   git clone https://github.com/zyr-ux/Synclo-Backend.git
   cd Synclo-Backend
   cp .env.example .env
   ```
   Open `.env` and configure your `SECRET_KEY` and `REFRESH_TOKEN_HASH_KEY`.

2. **Set Up Virtual Environment:**
   ```bash
   python -m venv .venv
   ```
   Activate the environment:
   * **Windows:** `.venv\Scripts\activate`
   * **macOS / Linux:** `source .venv/bin/activate`

   Install the project dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

3. **Run Migrations:**
   ```bash
   alembic upgrade head
   ```

4. **Launch the Server:**
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   The interactive API documentation (ReDoc) will be available at `http://localhost:8000/api/docs`.

---

## 🧪 Verification & Testing

Verify that your local changes do not break core logic by running the standardized pytest suite within your activated virtual environment:

```bash
pytest
```

Alternatively, run pytest directly using the virtual environment executable without activating it:

*   **Windows:**
    ```powershell
    .venv\Scripts\pytest.exe
    ```
*   **macOS / Linux:**
    ```bash
    .venv/bin/pytest
    ```

---

## 🤝 Contributing

Contributions are welcome! Before getting started, please review our architectural and development documentation:

*   📐 **[ARCHITECTURE.md](ARCHITECTURE.md):** Comprehensive overview of system architecture, Zero-Knowledge cryptographic sequences, real-time WebSocket protocol frames, and codebase structure.
*   🗺️ **[ROADMAP.md](ROADMAP.md):** Strategic milestones and planned future features.
*   🛠️ **[CONTRIBUTING.md](CONTRIBUTING.md):** Development guidelines, local environment setup, and contribution workflow.

---

## 📄 License

This project is licensed under the AGPL-3.0 License. See the [LICENSE](LICENSE) file for details.
