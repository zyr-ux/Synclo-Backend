# Contributing to Synclo Backend

Thank you for your interest in contributing to the Synclo Backend! This guide will help you set up your local development environment and understand the architecture, guidelines, and standards for contributing code to the project.

---

## 1. Project Overview

Synclo is a real-time, secure, zero-knowledge end-to-end encrypted clipboard synchronization service.

For exhaustive specifications on system architecture, cryptographic key derivations, REST endpoints, WebSocket wire frames, and database models, please consult **[ARCHITECTURE.md](ARCHITECTURE.md)**. If you are developing with AI coding assistants, please also review **[AGENTS.md](AGENTS.md)**.

- **Zero-Knowledge Architecture:** The server is solely an encrypted relay and blind storage mediator. Plaintext passwords, Master Keys, derived keys, or decrypted clipboard payloads must never reach the server, be accepted by APIs, or appear in logs.
- **Single-Node VPS / Homelab Focus:** The backend is designed exclusively as a single-node deployment (via Docker Compose or bare-metal SQLite and local Redis) for personal VPS or homelab servers. Multi-node clustering or distributed systems complexity is intentionally out of scope.
- **Data Encrypted at Rest & in Flight:** Clipboard content is encrypted client-side with AES-256-GCM before transmission. In production, transport security is strictly enforced via HTTPS/WSS.
- **Soft Delete & Deterministic Synchronization:** Deleted items transition into tombstone records with immediate payload eradication, ensuring reliable offline-to-online delta reconciliation across devices.

---

## 2. Technology Stack

- **Language:** Python 3.12+ (Docker runtime uses Python 3.14)
- **Web Framework:** FastAPI & Uvicorn
- **ORM & Database:** SQLAlchemy & SQLite (WAL mode with `BEGIN IMMEDIATE` write concurrency)
- **Database Migrations:** Alembic
- **Real-Time Pub/Sub & Rate Limiting:** Redis & FastAPILimiter
- **Push Notifications:** UnifiedPush (with SSRF protection, IP pinning, and auto-pruning)
- **Observability & Telemetry:** Prometheus metrics (`/metrics`)
- **Code Style & Linting:** Ruff
- **Type Checking:** ty
- **Testing:** Pytest & pytest-asyncio
- **Containerization:** Docker (multi-stage build) & Docker Compose

---

## 3. Local Development Setup

Follow these steps to set up your local development environment:

### Prerequisites
- Python 3.12 or newer installed.
- [uv](https://docs.astral.sh/uv/) package manager installed.
- Redis server running locally or via Docker (`docker run -d -p 6379:6379 redis:7-alpine`).
- Git installed.

### Step 1: Clone the Repository
```bash
git clone https://github.com/zyr-ux/Synclo-Backend.git
cd Synclo-Backend
```

### Step 2: Synchronize Environment & Dependencies
Synchronize project dependencies and initialize the virtual environment using `uv`:
```bash
uv sync
```
This automatically provisions the environment and installs development dependencies (`pytest`, `ruff`, etc.).

### Step 3: Configure Environment Variables
Copy the template configuration from [.env.example](.env.example):
```bash
# macOS/Linux
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

Review `.env` and set appropriate development keys:
- `SECRET_KEY` and `REFRESH_TOKEN_HASH_KEY`: Secure random strings (at least 32 and 16 characters respectively).
- `HTTPS_ONLY`: Set to `false` for local development.
- `DATABASE_URL`: Defaults to `sqlite:///./data/synclo.db`.
- `REDIS_URL`: Defaults to `redis://localhost:6379`.

### Step 4: Run Database Migrations
Migrations apply automatically on application startup, but you can also run them manually:
```bash
uv run alembic upgrade head
```

### Step 5: Start the Development Server
Run the FastAPI development server:
```bash
uv run uvicorn app.main:app --reload --port 8000
```
- API root: `http://localhost:8000`
- Interactive API docs (ReDoc): `http://localhost:8000/api/docs`
- Health check: `http://localhost:8000/api/health`
- Prometheus metrics: `http://localhost:8000/metrics`

---

## 4. Development Guidelines

To maintain code quality, security, and architectural simplicity, please adhere to the following standards:

### Core Architectural Rules
1. **Preserve Zero-Knowledge Invariants:** Plaintext passwords, Master Keys, derived keys, or decrypted clipboard content must never touch the server, be accepted in API schemas, or be logged.
2. **SQLite Concurrency Rule:** **Never call bare `db.commit()`**. All database mutations must use `run_in_write_transaction` or `async_run_in_write_transaction` from [app/database/engine.py](app/database/engine.py) to acquire immediate write locks (`BEGIN IMMEDIATE`) and prevent SQLite lock escalation deadlocks.
3. **Soft Deletes for Clipboard Entries:** 
   - Never execute raw `DELETE` SQL on active clipboard entries.
   - Use `soft_delete_clipboard` in [app/services/clipboard_service.py](app/services/clipboard_service.py) to toggle `is_deleted = True`, clear ciphertext/nonce payloads, unpin the item, and record `deleted_at`.
   - Broadcast tombstone frames over WebSockets and trigger background push notifications.
4. **Code Simplicity & Human Comprehension:** Write explicit, readable logic over clever abstractions. Avoid dense one-liners, speculative generalizations, or deep wrapper hierarchies. Code should be immediately understandable by any engineer without friction.
5. **Database Model Changes:** Any modification to models in [app/database/models.py](app/database/models.py) requires an Alembic migration:
   ```bash
   uv run alembic revision --autogenerate -m "describe your changes"
   ```
   Always inspect the generated script in `alembic/versions/` to verify constraints, indexes, and nullability, and run `uv run alembic check` to verify schema parity.
6. **Documentation Updates:** When adding a new endpoint, schema change, or system behavior, document the technical specification directly in **[ARCHITECTURE.md](ARCHITECTURE.md)**. If [README.md](README.md) needs updates, discuss it in your PR or ask repository maintainers first.

---

## 5. Verification Checklist (Before Submitting)

Before submitting a Pull Request, execute the full verification suite locally:

### 1. Code Style & Linting
Run Ruff to check formatting and code conventions:
```bash
uv run ruff check .
```

### 2. Type Checking
Run `ty` to verify type annotations across the codebase:
```bash
uv run ty check .
```

### 3. Migration & Schema Parity Check
Verify that all model definitions match migration scripts and no unapplied schema changes exist:
```bash
uv run alembic check
```

### 4. Automated Test Suite
Run the complete Pytest suite (all tests must pass, including migration application and schema parity verification via `tests/test_migrations.py`):
```bash
uv run pytest -v
```

---

## 6. Guidelines for Contributors Using AI Coding Agents

While we welcome the use of modern development tooling, including AI coding assistants (such as Antigravity, Claude, Cursor, ChatGPT, or Copilot), the following strict policies apply to all AI-assisted contributions:

- **Personal Code Ownership & Comprehension:** You are 100% accountable for every line of code you submit. Before opening a Pull Request, you must take the time to read, understand, and verify the changes yourself. If requested during review, **you are required to be able to explain the code you added**, including design decisions, concurrency implications, and error handling. Comments like *"the AI generated this"* or inability to explain the code will result in immediate PR rejection.
- **No Fully AI-Generated PRs (No Slop):** Pull requests that are blindly generated by AI—including generic, robotic AI-generated PR titles and descriptions, hallucinated bullet points, or unreviewed auto-generated diffs—**are not accepted** and will be closed immediately without review.
- **Human-Authored PR Descriptions:** Your PR title and description must be written by you (a human contributor). Clearly articulate what problem you are solving, why your approach was chosen, and describe your testing and verification steps in your own words.
- **Feed Guidelines to Your Agent:** If you use an agentic AI coding workflow, ensure you point your assistant to **[ARCHITECTURE.md](ARCHITECTURE.md)** and **[AGENTS.md](AGENTS.md)**. Your agent must respect our zero-knowledge invariant, single-node VPS/homelab constraint, explicit simplicity guidelines, and SQLite concurrency rules (`run_in_write_transaction`).

---

## 7. How to Submit a Pull Request

1. **Fork the Repository:** Create a personal fork on GitHub.
2. **Create a Topic Branch:** Use a descriptive branch name (e.g., `fix/sqlite-busy-timeout` or `feat/recovery-key-rotation`).
3. **Understand Your Changes:** Ensure you understand all added or modified logic thoroughly and can defend the changes during code review.
4. **Keep Changes Focused:** Separate refactoring from feature work or bug fixes.
5. **Pass All Verifications:** Ensure Ruff linting and all Pytest tests pass cleanly.
6. **Open a Pull Request:** Provide a genuine, human-authored description explaining what was changed, why it was changed, and note which verification steps were run.
