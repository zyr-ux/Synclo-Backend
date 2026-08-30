# Synclo Backend

[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat&logo=redis&logoColor=white)](https://redis.io/)

Synclo is a FastAPI-based backend service designed to facilitate secure, real-time clipboard synchronization across multiple client devices (Mobile, Desktop, Web).

It operates on a **Zero-Knowledge Architecture**, ensuring that all clipboard content is encrypted and decrypted strictly on the client side. The server never learns user passwords, encryption keys, or the plaintext contents of the clipboard payloads.

---

## 🚀 Key Features

*   🔒 **Zero-Knowledge Security:** Plaintext passwords, Master Keys, and decrypted clipboard entries never touch the server. All payloads are AES-encrypted before transmission.
*   ⚡ **Real-Time Push Synchronization:** Employs WebSockets for instant propagation of clipboard updates across client devices.
*   📲 **Mobile Background Push Notifications:** Integrated with UnifiedPush / FCM distributors for energy-efficient silent background wake-ups on Android devices.
*   🌐 **Multi-Instance Scalability:** Uses Redis Pub/Sub underneath to distribute WebSocket broadcasts, enabling the backend to scale across multiple server nodes.
*   🔄 **Smart Delta Synchronization:** Employs a soft-delete (tombstone) strategy to support robust synchronization for devices transitioning between offline and online states.
*   📌 **Granular Pin Management:** Lightweight dedicated pinning system ensuring pinned clipboard items are preserved during bulk history purges and immune to auto-pruning.
*   📊 **Configurable Quota & Auto-Pruning:** User-customizable clipboard history depth limits with automatic background pruning of older unpinned entries.
*   📈 **Observability & Prometheus Telemetry:** Exposes anonymized, privacy-preserving operational metrics at `/metrics`.
*   🛡️ **Advanced Session Security:** Uses Refresh Token Rotation, token reuse detection, and global rate limiting to protect against session theft and brute-force attacks.

---

## 📁 Repository Documentation Map

For detailed guides, please refer to the following documents:

*   📐 **[ARCHITECTURE.md](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/ARCHITECTURE.md):** Comprehensive overview of the system design, Zero-Knowledge cryptographic sequences, real-time WebSocket protocol frames, detailed REST API specs, and a file-by-file codebase guide.
*   🗺️ **[ROADMAP.md](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/ROADMAP.md):** Strategic product roadmap detailing completed milestones and planned future features.
*   🛠️ **[CONTRIBUTING.md](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/CONTRIBUTING.md):** Step-by-step instructions for local virtual environment configuration, running migrations, and setting up Redis.
*   🤖 **[AGENTS.md](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/AGENTS.md):** Playbook and coding constraints for AI coding agents developing on this codebase.

---

## ⚙️ Quick Start

### Option 1: Running with Docker Compose (Recommended)
The easiest way to start the server alongside its Redis instance is using Docker Compose:

```bash
docker compose up -d --build
```
The application will boot up at `http://localhost:8000`. You can inspect the logs using `docker compose logs -f`.

### Option 2: Running Locally (Manual Setup)
1.  **Clone & Configure:**
    ```bash
    git clone https://github.com/zyr-ux/Synclo-Backend.git
    cd Synclo-Backend
    cp .env.example .env  # Configure your SECRET_KEY and REFRESH_TOKEN_HASH_KEY
    ```
2.  **Set Up Environment:**
    ```bash
    python -m venv .venv
    # Windows: .venv\Scripts\activate | Unix: source .venv/bin/activate
    pip install -e ".[dev]"
    ```
3.  **Run Migrations:**
    ```bash
    alembic upgrade head
    ```
4.  **Launch the Server:**
    ```bash
    uvicorn app.main:app --reload --port 8000
    ```

---

## 🗃️ Directory Structure

```text
Synclo-Backend/
├── app/
│   ├── core/         # Configuration, DB connection, constants, logging, metrics
│   ├── endpoints/    # Routers (Auth, Devices, Clipboard, WebSockets)
│   ├── models/       # SQLAlchemy DB schemas
│   ├── schemas/      # Pydantic v2 request/response models
│   ├── services/     # Core logic (Auth, Serialization, Tasks, Push Service)
│   ├── websockets/   # WebSocket Connection Manager with Redis Pub/Sub listener
│   └── main.py       # Application initialization and startup routines
├── alembic/          # Database migration history
├── data/             # Persistent directory for SQLite database
├── logs/             # Persistent directory for rotative logs
├── tests/            # Automated pytest test suite
├── compose.yaml      # Docker Compose orchestration
├── pyproject.toml    # Project metadata, dependencies, and build configuration
├── ROADMAP.md        # Strategic engineering roadmap
└── ARCHITECTURE.md   # Architectural & protocol reference
```

---

## 🧪 Verification & Testing

Verify that your local changes do not break core logic by running the standardized pytest suite within your virtual environment (`.venv`):

```bash
# With .venv activated:
pytest

# Or running directly via virtual environment executable:
# Windows:
.venv\Scripts\pytest.exe
# macOS / Linux:
.venv/bin/pytest
```

---

## 📄 License

This project is licensed under the AGPL-3.0 License. See the [LICENSE](LICENSE) file for details.
