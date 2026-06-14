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
*   🌐 **Multi-Instance Scalability:** Uses Redis Pub/Sub underneath to distribute WebSocket broadcasts, enabling the backend to scale across multiple server nodes.
*   🔄 **Smart Delta Synchronization:** Employs a soft-delete (tombstone) strategy to support robust synchronization for devices transitioning between offline and online states.
*   🛡️ **Advanced Session Security:** Uses Refresh Token Rotation, token reuse detection, and global rate limiting to protect against session theft and brute-force attacks.

---

## 📁 Repository Documentation Map

For detailed guides, please refer to the following documents:

*   📐 **[ARCHITECTURE.md](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/ARCHITECTURE.md):** Comprehensive overview of the system design, Zero-Knowledge cryptographic sequences, real-time WebSocket protocol frames, detailed REST API specs, and a file-by-file codebase guide.
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
    pip install -r requirements.txt
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
│   ├── core/         # Configuration, DB connection, constants, logging
│   ├── endpoints/    # Routers (Auth, Devices, Clipboard, WebSockets)
│   ├── models/       # SQLAlchemy DB schemas
│   ├── schemas/      # Pydantic v2 request/response models
│   ├── services/     # Core logic helpers (Auth, Serialization, Tasks)
│   ├── websockets/   # WebSocket Connection Manager with Redis Pub/Sub listener
│   └── main.py       # Application initialization and startup routines
├── alembic/          # Database migration history
├── data/             # Persistent directory for SQLite database
├── logs/             # Persistent directory for rotative logs
├── tests/            # Automated verification integration scripts
└── docker-compose.yaml
```

---

## 🧪 Verification & Testing

Verify that your local changes do not break core logic by running:

```bash
python -m tests.verify_delta_sync
python -m tests.verify_device_os
python -m tests.verify_offset_pagination
```

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
