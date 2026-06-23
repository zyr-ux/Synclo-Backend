# AI Agent Development Guidelines (AGENTS.md)

Welcome, AI Agent! This document contains critical rules, context, and patterns for developing, debugging, or extending the Synclo Backend. Read this carefully to avoid violating the core system invariants or breaking the client-synchronization protocol.

---

## 1. Core Architectural Context

Synclo is a FastAPI-based server designed for secure, real-time clipboard synchronization across multiple client devices. It works under a **Zero-Knowledge Architecture**. 

Before editing any code, please review the **[ARCHITECTURE.md](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/ARCHITECTURE.md)** file for a comprehensive layout of the architecture, visual sequence/flow diagrams, and a file-by-file analysis.

- **Security Invariant:** The server is only a mediator and storage engine for *encrypted payload data*. It must never see or know the user's password, master keys, or decrypted clipboard content.
- **Real-time Engine:** WebSockets are used for push-based clipboard updates. It uses a custom `ConnectionManager` utilizing Redis Pub/Sub underneath to support multiple running server nodes.
- **Sync Model:** SQLite stores clipboard entries. Offline clients sync using a delta mechanism based on the entry's `updated_at` timestamp.

---

## 2. Invariants & Rules for AI Agents

### Rule 1: Zero-Knowledge Invariance
* **No Plaintext Passwords / Master Keys:** Never introduce code or API changes that accept, store, or log plaintext passwords or decrypted Master Keys.
* **No Plaintext Payloads:** Clipboard content is encrypted on the client side. The database fields `ciphertext` and `nonce` are base64-encoded binary blobs. Do not add logic attempting to decrypt, inspect, or format the content of these payloads on the server side.

### Rule 2: Soft Delete & Tombstones Pattern
*   **No Direct DB Purges:** When an entry is deleted, it must be soft deleted. Set `is_deleted = True` and populate `deleted_at` with the server time. Do not run hard `DELETE` commands except for account deletion (`DELETE /api/v1/delete`).
*   **Retention Cleanup:** Tombstones are automatically cleaned up after 30 days (`TOMBSTONE_RETENTION_DAYS`). If you modify the cleanup logic or the database models, ensure the 30-day cutoff logic remains correct to prevent synchronization anomalies.
*   **Pin System Preservation:** Bulk deletion requests (`DELETE /api/v1/clipboard`) must preserve items that are pinned (`is_pinned = True`). Pinned items can only be deleted via targeted single-item deletion (`DELETE /api/v1/clipboard/{id}`), which soft-deletes the item and sets `is_pinned = False`.
*   **Deletion Broadcasts:** When a soft delete is triggered (either via REST API or WebSocket), a deletion notification must be broadcasted via WebSocket to all other connected client devices for that user:
  ```json
  {
    "id": "uuid_string",
    "is_deleted": true,
    "is_pinned": false,
    "timestamp": "ISO8601_timestamp_Z",
    "ciphertext": null,
    "nonce": null,
    "blob_version": 1
  }
  ```

### Rule 3: Database & Alembic Migrations
*   **Migrations are Required:** Any schema changes in `app/models/models.py` must be accompanied by an Alembic migration script. Do not write raw SQL migrations or modify existing migration files.
*   **Generate Migration:** Use the CLI to generate a migration script:
  ```bash
  alembic revision --autogenerate -m "description_of_change"
  ```
*   **Startup Behavior:** The application runs Alembic migrations automatically on startup via `app/main.py`. Ensure your changes do not break this startup routine or deadlock the DB connection.

### Rule 4: WebSocket Connections & Scale-Out
*   **Connection Lifecycle:** The `ConnectionManager` in `app/websockets/connection_manager.py` tracks active sockets.
*   **Multi-Instance (Redis):** Keep in mind that when an event is broadcasted, it uses Redis Pub/Sub to reach other server nodes. Always use `manager.broadcast_to_user` so that the event gets published to Redis and distributed.
*   **WebSocket Close Codes:** Always use the defined close codes when closing connections:
  - `4001`: Token Expired
  - `4003`: Device deleted remotely (send a `{"type": "device_deleted"}` JSON message right before closing).

### Rule 5: Rate Limiting & Safety
*   **Apply Limiter:** Sensitive and write endpoints must use the `FastAPILimiter` dependency. Example:
  ```python
  dependencies=[Depends(RateLimiter(times=30, seconds=60))]
  ```

---

## 3. Directory Structure Map

Refer to this map to find where to add code:
* `app/core/`: Configuration (`config.py`), constants (`constants.py`), database session initialization (`database.py`), logging settings.
* `app/endpoints/`: FastAPI routers split by domain (`auth_endpoints.py`, `device_endpoints.py`, `clipboard_endpoints.py`, `websocket_endpoints.py`).
* `app/models/`: SQLAlchemy database models.
* `app/schemas/`: Pydantic input/output schemas (using Pydantic v2).
* `app/services/`: Core logic (such as `auth.py` helpers and background `utils.py` tasks).
* `app/websockets/`: Real-time WebSocket connection handling and Redis Pub/Sub listener.
* `tests/`: End-to-end and mock-based integration test scripts.

---

## 4. Verification Check list for Agents

Before concluding your task, you **must** run the verification suite to ensure no regressions were introduced.
Use `run_command` to execute the following scripts:
```bash
# Verify delta synchronization logic (checks tombstone handling and sync timestamp offsets)
python -m tests.verify_delta_sync

# Verify device additions and revoking
python -m tests.verify_device_os

# Verify pagination stability
python -m tests.verify_offset_pagination

# Verify clipboard pin system logic, bulk delete, and single delete behavior
python -m tests.verify_clipboard_pin
```
If any of these verification scripts fail, resolve the issues before presenting your solution.
