# Synclo Backend

[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python 3.14](https://img.shields.io/badge/Python-3.14-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat&logo=redis&logoColor=white)](https://redis.io/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/zyr-ux/Synclo-Backend/ci.yml?style=flat)](https://github.com/zyr-ux/Synclo-Backend/actions/workflows/ci.yml)

**Synclo** is a secure, cross-platform clipboard manager that keeps your clipboard seamlessly in sync across your devices (Desktop, Mobile, Web).

This repository contains the **Synclo Backend**—the server that powers real-time synchronization, device management, and background push notifications for the Synclo client apps.

Built on a **Zero-Knowledge Architecture**, the backend acts strictly as an encrypted mediator: all encryption and decryption happen directly on your client devices. The server never learns your passwords, encryption keys, or the plaintext contents of your clipboard.

---

## 🚀 Key Features

*   🔒 **Zero-Knowledge Architecture:** End-to-end client encryption ensures passwords, Master Keys, and decrypted clipboard contents never touch the server.
*   ⚡ **Instant Real-Time Sync:** WebSockets backed by Redis Pub/Sub deliver immediate clipboard propagation across all active devices.
*   📲 **Silent Mobile Wake-Ups:** Native UnifiedPush integration enables energy-efficient, background synchronization on Android.
*   🔄 **Reliable Offline Catch-Up:** Smart delta synchronization and tombstone records ensure devices seamlessly reconcile after being offline.
*   📊 **Configurable Data Retention:** Automated server-side lifecycle pruning for old clips and tombstones keeps local SQLite storage fast and lightweight.
*   🛡️ **Hardened Session Security:** Built-in Refresh Token Rotation, token reuse detection, Redis rate limiting, and strict HTTPS/WSS enforcement.

---

## 🌍 Default Server & Client Connection

A default, publicly hosted Synclo server instance is maintained for general use and comes **pre-configured out of the box** in the official Synclo client applications:

*   🌐 **Default API Base URL:** `https://synclo.zyrux.dev/api/v1`
*   ⚡ **WebSocket Sync Endpoint:** `wss://synclo.zyrux.dev/ws/v1/sync`

Thanks to Synclo's **Zero-Knowledge Architecture**, all clipboard payloads are encrypted client-side using your local keys before transmission—the hosted server cannot decrypt or inspect your passwords, keys, or clipboard contents.

### Using a Custom Self-Hosted Server

If you prefer complete data sovereignty by self-hosting this backend, you can easily switch servers in the Synclo client apps:
1. Deploy your server instance using the [Deployment](#deployment) instructions below.
2. In the Synclo client app, navigate to **Settings** → **Server URL**
3. Switch from the default server and enter your custom self-hosted domain (e.g., `https://synclo.yourdomain.com`).

---

<a id="deployment" name="deployment"></a>

## 🚀 Deployment (Docker Compose)

The recommended way to self-host Synclo is using **Docker Compose** behind a reverse proxy (such as **Caddy** or **Nginx**) that handles HTTPS and TLS termination. This runs the pre-built Synclo backend container alongside Redis without requiring manual source compilation or cloning the repository.

### 1. Create Project Directory

Create the directory for Synclo along with subdirectories for persistent SQLite data and application logs:

```bash
mkdir -p Synclo-Backend/data Synclo-Backend/logs
cd Synclo-Backend
```

### 2. Create `compose.yaml`

Save the following configuration as `compose.yaml` in your `Synclo-Backend/` directory:

```yaml
services:
  synclo-backend:
    image: ghcr.io/zyr-ux/synclo-backend:latest
    container_name: synclo-backend
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      SECRET_KEY: "change_this_to_a_random_hex_key" # minimum 32 characters
      REFRESH_TOKEN_HASH_KEY: "change_this_to_a_random_hex_key" # minimum 16 characters
      ENVIRONMENT: "production"
      HTTPS_ONLY: "true"
      CLIPBOARD_RETENTION_DAYS: "30"
      TOMBSTONE_RETENTION_DAYS: "30"
      REDIS_URL: "redis://redis:6379"
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
    command:
      - redis-server
      - --maxmemory
      - 256mb
      - --maxmemory-policy
      - noeviction
    expose:
      - 6379
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep PONG"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 5s
```

### 3. Generate Secret Keys & Configure

Generate two random 32-byte hexadecimal secret keys:

```bash
openssl rand -hex 32
```

Run this twice—once for `SECRET_KEY` and once for `REFRESH_TOKEN_HASH_KEY`—and insert these generated keys into your `compose.yaml`.

### 4. Start the Stack

Launch the containers in detached mode:

```bash
docker compose up -d
```

#### 📁 Persistent Host Data & Logs

Docker mounts your host directories (`./data` and `./logs`) into the container. All database files and logs are directly accessible on your host machine inside `Synclo-Backend/`:

```text
Synclo-Backend/
├── compose.yaml
├── data/
│   ├── synclo.db               # SQLite database file (WAL mode)
│   └── backups/                # Database backup snapshots
└── logs/
    └── server.log              # Live application logs
```

Inspect live application logs:
```bash
docker compose logs -f
# Or directly on your host machine:
tail -f logs/server.log
```

### 5. Configure Reverse Proxy (Caddy Example)

Synclo binds locally to `127.0.0.1:8000` to prevent direct unencrypted exposure. Expose Synclo to your domain with automatic HTTPS certificates using a host-level Caddy reverse proxy:

1. Open your host's Caddy configuration:
   ```bash
   sudo vim /etc/caddy/Caddyfile
   ```

2. Add the reverse proxy block, replacing `synclo.yourdomain.com` with your actual domain:
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

3. Reload Caddy:
   ```bash
   sudo systemctl reload caddy
   ```

4. Verify your deployment is healthy:
   ```bash
   curl -I https://synclo.yourdomain.com/api/health
   ```

---

<a id="development" name="development"></a>

## 💻 Local Development

For developers and contributors running, modifying, and testing Synclo locally from source.

### 1. Clone the Repository

Clone the project from GitHub and switch to the repository root:

```bash
git clone https://github.com/zyr-ux/Synclo-Backend.git
cd Synclo-Backend
```

### 2. Install Dependencies & Dev Packages

Synclo uses [uv](https://docs.astral.sh/uv/) for fast, reproducible Python dependency and virtual environment management.

If you don't have `uv` installed, install it via:
```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Initialize the virtual environment and download/install all core runtime dependencies alongside all development packages:

```bash
uv sync
```

### 3. Configure Environment Variables

Create your local `.env` configuration from the provided template:

```bash
# Linux / macOS
cp .env.example .env

# Windows (PowerShell)
Copy-Item .env.example .env
```

Generate secret keys using `openssl rand -hex 32` and update `SECRET_KEY` and `REFRESH_TOKEN_HASH_KEY` in `.env`. For local development, keep the defaults:
```ini
ENVIRONMENT=development
HTTPS_ONLY=false
DATABASE_URL=sqlite:///./data/synclo.db
REDIS_URL=redis://localhost:6379
```

### 4. Start Redis

Redis is required for WebSocket pub/sub messaging and rate limiting. Run a local Redis container:

```bash
docker run -d --name synclo-redis -p 6379:6379 redis:7-alpine
```

### 5. Run Database Migrations (Optional)

Database migrations run automatically on server startup via FastAPI's lifespan handler, but you can also execute them manually and verify schema parity:

```bash
uv run alembic upgrade head
uv run alembic check
```

### 6. Launch the Server

Start the development server with hot reload:

```bash
uv run uvicorn app.main:app --reload --port 8000
```

Once running:
* 🌐 **API Base URL:** `http://localhost:8000`
* 📚 **Interactive ReDoc Documentation:** `http://localhost:8000/api/docs`
* 🔍 **Swagger UI:** `http://localhost:8000/docs`
* 🩺 **Health Check:** `http://localhost:8000/api/health`
* 📊 **Prometheus Metrics:** `http://localhost:8000/metrics`

---

## ⚙️ Configuration Reference

The following environment variables can be configured in your `.env` file or container environment:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `SECRET_KEY` | *(Required)* | Secret key used for signing JWT access tokens (minimum 32 characters). |
| `REFRESH_TOKEN_HASH_KEY` | *(Required)* | Secret key used for HMAC hashing of refresh tokens (minimum 16 characters). |
| `ALGORITHM` | `HS256` | JWT signing algorithm (`HS256`, `HS384`, or `HS512`). |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | JWT access token expiration time in minutes (allowed range: `1`–`60`). |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `30` | Refresh token lifespan in days before re-authentication is required (allowed range: `1`–`365`). |
| `DATABASE_URL` | `sqlite:///./data/synclo.db` | SQLAlchemy database connection string (`sqlite:////app/data/synclo.db` in container setups). |
| `REDIS_URL` | `redis://redis:6379` | Redis connection string for WebSocket pub/sub broadcasting and rate limiting (`redis://localhost:6379` in local dev). |
| `HTTPS_ONLY` | `false` | Enforces strict HTTPS redirection (`307`), HSTS headers, and secure WebSockets (`WSS`). Defaults to `false` if omitted. |
| `ENVIRONMENT` | `development` | Deployment environment (`development` or `production`). Production enforces strict push endpoint security constraints. |
| `CLIPBOARD_RETENTION_DAYS` | `30` | Auto-pruning retention lifecycle in days for unpinned clipboard items (`0` to disable). Pinned items are immune. |
| `TOMBSTONE_RETENTION_DAYS` | `30` | Retention duration in days for deletion records (tombstones) enabling offline client synchronization. |
| `BACKUP_ENCRYPTION_KEY` | `None` | Optional Fernet key used by operational backup utilities (`app/utilities/backup_db.py`) to encrypt SQLite database snapshots (`.db.enc`). |
| `BACKUP_RETENTION_DAYS` | `30` | Retention duration in days for database backup snapshots before automatic pruning. |
| `BACKUP_DIR` | `data/backups` | Directory path where SQLite database backups are stored. |

---

## 🧪 Verification & Testing

Verify that your local changes pass all code style, typing, schema parity, and testing checks:

```bash
uv run ruff check .
uv run ty check .
uv run alembic check
uv run pytest -v
```

---

## 🤝 Contributing

Contributions are welcome! Before getting started, please review our architectural and development documentation:

*   📐 **[ARCHITECTURE.md](ARCHITECTURE.md):** Comprehensive overview of system architecture, Zero-Knowledge cryptographic sequences, real-time WebSocket protocol frames, and codebase structure.
*   🗺️ **[ROADMAP.md](ROADMAP.md):** Strategic milestones and planned future features.
*   🛠️ **[CONTRIBUTING.md](CONTRIBUTING.md):** Development guidelines, local environment setup, and contribution workflow.
*   🤖 **[AGENTS.md](AGENTS.md):** Guidelines, architectural constraints, and verification workflows for AI coding assistants and contributors.

---

## 📄 License

This project is licensed under the AGPL-3.0 License. See the [LICENSE](LICENSE) file for details.
