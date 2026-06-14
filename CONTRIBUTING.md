# Contributing to Synclo Backend

Thank you for your interest in contributing to the Synclo Backend! This guide will help you set up your local development environment and understand the architecture, guidelines, and standards for contributing code to the project.

---

## 1. Project Overview

Synclo is a real-time, secure, end-to-end encrypted clipboard synchronization service. 

For a detailed breakdown of the backend system architecture, security design, and file-by-file code explanations, please refer to the **[ARCHITECTURE.md](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/ARCHITECTURE.md)** document.

- **Zero-Knowledge Architecture:** The server never sees the user's raw password, the decryption keys (Master Key), or the raw clipboard data.
- **Data Encrypted at Rest:** Clipboard content is encrypted on the client side before being transmitted to the server.
- **Soft Delete & Tombstones:** A soft delete strategy ensures offline/online client synchronization works flawlessly, even after long periods of offline use.

---

## 2. Technology Stack

- **Language:** Python 3.12+
- **Web Framework:** FastAPI
- **ORM & DB:** SQLAlchemy & SQLite (for local persistence)
- **Migrations:** Alembic
- **Real-Time Pub/Sub:** Redis
- **Containerization:** Docker & Docker Compose
- **Security:** OAuth2 (JWT), Bcrypt (Auth Key Hashing), Fernet/AES-GCM (used on client side)

---

## 3. Local Development Setup

Follow these steps to set up your local development environment:

### Prerequisites
- Python 3.12 installed on your machine.
- Redis server running locally or via Docker.
- (Optional) Docker and Docker Compose installed.

### Step 1: Clone the Repository
```bash
git clone https://github.com/zyr-ux/Synclo-Backend.git
cd Synclo-Backend
```

### Step 2: Set Up Virtual Environment
Create and activate a Python virtual environment:

**On macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**On Windows:**
```cmd
python -m venv .venv
.venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables
Create a `.env` file in the root directory. You can copy the structure below:

```env
# JWT settings
SECRET_KEY=your_secure_random_hex_string
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_HASH_KEY=your_hmac_secret_key_at_least_16_chars
REFRESH_TOKEN_EXPIRE_DAYS=30

# DB settings
DATABASE_URL=sqlite:///./data/clipboard.db
REDIS_URL=redis://localhost:6379

# Soft Delete settings
TOMBSTONE_RETENTION_DAYS=30
```

### Step 5: Run Database Migrations
Migrations run automatically on application startup. However, you can also run them manually using:
```bash
alembic upgrade head
```

### Step 6: Start the Development Server
Run the FastAPI development server:
```bash
uvicorn app.main:app --reload --port 8000
```
The server will start at `http://localhost:8000`. You can access the interactive API documentation at `http://localhost:8000/docs`.

---

## 4. Development Guidelines

To maintain code quality and security, please follow these guidelines when writing code:

### Core Architectural Rules
1. **Preserve Zero-Knowledge Security:** Under no circumstances should the server receive, log, store, or process raw passwords, master keys, or decrypted clipboard content.
2. **Use Soft Deletes for Clipboard Entries:** 
   - Never run `DELETE` queries on clipboard entries directly.
   - Toggle `is_deleted = True` and set `deleted_at = datetime.now(timezone.utc)`.
   - Ensure you broadcast a deletion event to the client over WebSockets upon deletion.
3. **Database Changes:** 
   - If you modify database models in `app/models/models.py`, you **must** generate a new migration revision:
     ```bash
     alembic revision --autogenerate -m "describe your changes"
     ```
   - Review the generated script in `/alembic/versions` to ensure it is correct.
4. **Pydantic Schema Validation:** Keep request/response schemas strictly validated in `app/schemas/schemas.py`.

---

## 5. Running Tests

Before submitting a Pull Request, verify that all tests pass.

### Execution
You can run the verification scripts directly:
```bash
# Verify delta synchronization logic (incorporates mock Redis setup)
python -m tests.verify_delta_sync

# Verify device OS-specific flows
python -m tests.verify_device_os

# Verify offset pagination and sync stability
python -m tests.verify_offset_pagination
```

Ensure you have your virtual environment active and dependencies installed prior to running tests.

---

## 6. How to Submit a Pull Request

1. **Fork the Repository:** Create a copy of the repository under your GitHub account.
2. **Create a Feature Branch:** Name your branch descriptively (e.g., `feature/add-websocket-heartbeat` or `fix/jwt-expiration`).
3. **Commit Your Changes:** Keep commits small and write meaningful commit messages.
4. **Push & Create PR:** Push your branch to GitHub and open a Pull Request. Provide a clear summary of what your changes accomplish.
