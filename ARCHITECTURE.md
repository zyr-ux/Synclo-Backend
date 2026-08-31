# Synclo Backend Architecture & Protocol Reference (ARCHITECTURE.md)

This document provides a comprehensive overview of the Synclo Backend architecture and client-side integration protocol. It details the high-level system design, Zero-Knowledge cryptographic flows, real-time WebSocket messaging schemas, detailed REST API request/response specifications, and a file-by-file codebase guide.

---

## 1. High-Level System Architecture

Synclo is a real-time, secure, end-to-end encrypted clipboard synchronization service designed around a **Zero-Knowledge Architecture**. The backend server serves as a mediator and encrypted storage engine, never learning the user's password, data decryption keys, or plaintext clipboard payloads.

### Architecture Diagram

```mermaid
graph TD
    Client1["Client Device 1 (Mobile/Desktop)"] ---|"WebSockets (wss/ws)"| WS_End["WebSocket Endpoints"]
    Client2["Client Device 2 (Mobile/Desktop)"] ---|"WebSockets (wss/ws)"| WS_End
    Client1 -->|"REST HTTP Requests"| REST_End["REST API Endpoints"]
    Client2 -->|"REST HTTP Requests"| REST_End
    
    subgraph FastAPI ["Application Container"]
        WS_End
        REST_End
        Manager["ConnectionManager"]
        AuthServ["Auth Service"]
        CleanupServ["Cleanup Service"]
        PushServ["Push Notification Service"]
    end
    
    WS_End --- Manager
    REST_End --> AuthServ
    WS_End --> DB[("SQLite Database")]
    REST_End --> DB
    CleanupServ --> DB
    REST_End --> PushServ
    WS_End --> PushServ
    PushServ --> Dist["UnifiedPush Distributors / Webhooks"]
    
    Manager ---|"Redis Pub/Sub"| Redis[("Redis Cache & Pub/Sub")]
```

*   **REST HTTP Endpoints:** Handle authentication, session tokens, device registrations, and fallback manual clipboard transfers.
*   **WebSocket Endpoints:** Maintain persistent connections for low-latency, real-time clipboard sync.
*   **ConnectionManager:** Coordinates WebSocket sessions. Uses Redis Pub/Sub underneath to distribute sync events across horizontally scaled server instances.
*   **Database (SQLite):** Stores user login hashes, device registries, session tokens, and encrypted clipboard entry history (tombstones).
*   **Cleanup Service:** Background workers running periodic purges on old expired data and tombstones.

---

## 2. Zero-Knowledge Cryptography & Authentication Flow

The server does not know or store raw passwords or master decryption keys. All encryption and decryption happen client-side.

### Cryptographic Invariants

| Key / Parameter | Origin | Server Knowledge | Purpose | Recommended Algorithm |
| :--- | :--- | :--- | :--- | :--- |
| **KDF Salt** | Client (on Reg) | Plaintext (stored) | Used to derive client-side keys | CSPRNG 16 bytes (base64) |
| **Master Key (MK)** | Client (on Reg) | None (never sent) | Encrypts local clipboard payload | CSPRNG 32 bytes (base64) |
| **Derived Key (DK)** | Client (computed) | None (never sent) | Encrypts Master Key locally | PBKDF2-HMAC-SHA256 or Argon2id |
| **Auth Key (AK)** | Client (computed) | Bcrypt Hash only | Authenticates API requests | HMAC-SHA256 of DK |
| **Encrypted MK** | Client (computed) | Ciphertext (stored) | Restores Master Key after login | AES-256-GCM of MK using DK |
| **Clipboard Cipher** | Client (computed) | Ciphertext (stored) | Protects clipboard content | AES-256-GCM of payload using MK |

---

### Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Client as Client App
    actor Server as Synclo Backend
    
    Note over Client: Registration Flow
    Client->>Client: Generate random 32-byte Master Key (MK)
    Client->>Client: Generate random 16-byte KDF Salt
    Client->>Client: Derive Derived Key (DK) = PBKDF2(Password, Salt, iterations=100,000)
    Client->>Client: Compute Auth Key (AK) = HMAC-SHA256(DK, "auth_key")
    Client->>Client: Encrypt Master Key (MK) using DK via AES-GCM -> Encrypted MK (EMK)
    Client->>Server: POST /api/v1/register (Email, AK, EMK, Salt, Device details)
    Note over Server: Bcrypt hashes Auth Key (AK)<br/>Stores record in DB
    Server-->>Client: Access Token (JWT) + Refresh Token
    
    Note over Client: Login Flow (Fresh Device / New Session)
    Client->>Server: GET /api/v1/auth/salt?email=user@example.com
    Server-->>Client: KDF Salt
    Client->>Client: Derive DK = PBKDF2(Password, Salt, iterations=100,000)
    Client->>Client: Compute AK = HMAC-SHA256(DK, "auth_key")
    Client->>Server: POST /api/v1/login (Email, AK, Device details)
    Server-->>Client: Tokens + Encrypted MK (EMK)
    Client->>Client: Decrypt EMK using DK via AES-GCM -> Restores Master Key (MK)
```

#### A. Initial Registration
1.  **Generate Local Secret Elements:** Generate a 256-bit `Master Key` and a random 128-bit `Salt` client-side.
2.  **Key Derivation:** Derive a 256-bit `Derived Key` via PBKDF2-HMAC-SHA256 (100,000 iterations). Compute the `Auth Key` by taking the HMAC-SHA256 of the `Derived Key`:
    $$\text{Auth Key} = \text{HMAC-SHA256}(\text{Derived Key}, \text{"auth\\_key"})$$
3.  **Local Wrapping:** Encrypt the `Master Key` using the `Derived Key` via **AES-256-GCM** to output the `Encrypted Master Key`.
4.  **Transmission:** Submit the base64-encoded `Auth Key`, `Encrypted Master Key`, `Salt`, KDF version, and device data to `POST /api/v1/register`.

#### B. Logging In
1.  **Retrieve Salt:** Query `GET /api/v1/auth/salt?email=<email>` to fetch the KDF Salt.
2.  **Derivation:** Recompute the `Derived Key` and `Auth Key` using the password and salt.
3.  **Authentication:** Send the base64-encoded `Auth Key` to `POST /api/v1/login` alongside device identifiers.
4.  **Restore Session:** The login response yields the JWT session tokens and the stored `Encrypted Master Key`. Decrypt the `Encrypted Master Key` using the computed `Derived Key` via AES-256-GCM to restore the plaintext `Master Key` in the client's memory.

#### C. Password Changing (Master Key Re-wrapping)
1.  Derive the current `Derived Key` and `Auth Key` from the old password.
2.  Generate a new random `Salt`.
3.  Derive the **new** `Derived Key` and **new** `Auth Key` using the new password and salt.
4.  Re-encrypt (re-wrap) the raw `Master Key` (which remains unchanged to preserve existing database history) using the **new** `Derived Key` to create a **new** `Encrypted Master Key`.
5.  Send the old and new key material to `POST /api/v1/password/change`.

> [!WARNING]
> Do not change the `Master Key` during a password change. Doing so will invalidate all existing clipboard history stored in the database, making it impossible to decrypt them. Only re-wrap the existing Master Key using the new Derived Key.

---

## 3. Data Synchronization & Tombstone Pattern

To synchronize deletions to offline clients, Synclo uses a soft-deletion pattern:
- **Tombstones:** Deleted clipboard items are not purged immediately. They are marked `is_deleted = True` and given a `deleted_at` server timestamp.
- **Delta Sync:** Offline clients query `/api/v1/clipboard/sync` using a `since` timestamp parameter. The server returns all clipboard updates (inserts, modifications, and tombstones) where `updated_at > since`.
- **Pin System:** Active clipboard entries can be pinned (`is_pinned = True`), keeping them synchronized across devices. Pinned entries are bypassed and preserved during a bulk delete request (`DELETE /api/v1/clipboard`). They are only soft-deleted when targeted specifically (`DELETE /api/v1/clipboard/{id}`), which automatically sets `is_pinned = False`.
- **Retention Cleanup:** A background thread running every 24 hours purges tombstones older than `TOMBSTONE_RETENTION_DAYS` (default: 30 days) to prevent database bloating.
- **Expired Sync Prevention:** If a client requests a delta sync with a `since` timestamp older than the 30-day retention cutoff, the server rejects it with `410 Gone`. The client is forced to wipe its local database and perform a fresh full sync.

---

## 4. WebSocket Protocol (Real-time Synchronization)

The WebSocket endpoint provides push-based real-time clipboard synchronization across all authorized active devices.

*   **Endpoint:** `ws://<HOST>/ws/v1/sync` (local) or `wss://<HOST>/ws/v1/sync` (production)
*   **Protocol Handshake:** Must include the header: `Authorization: Bearer <access_token>`.

### Message Protocols (JSON Frames)

#### A. Clipboard Data Push (Client ➔ Server)
When the client copies a text, it encrypts the data using the `Master Key` (AES-256-GCM), encoding both cipher text and IV as base64, and sends:
```json
{
  "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
  "timestamp": "2026-06-14T14:15:30.123Z",
  "ciphertext": "dGhpcyBpcyBzZWNyZXQ...",
  "nonce": "YTM4OTJkOWM...",
  "blob_version": 1,
  "is_deleted": false,
  "is_pinned": false
}
```

#### B. Clipboard Deletion Broadcast (Client ➔ Server)
If a client soft-deletes a clipboard entry:
```json
{
  "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
  "timestamp": "2026-06-14T14:18:00.000Z",
  "is_deleted": true
}
```
*   `ciphertext` and `nonce` must be omitted or sent as `null` to ensure immediate server data purging (tombstoning).

#### C. Server Acknowledgment (Server ➔ Client)
Sent after the database write succeeds:
```json
{
  "type": "ack",
  "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9"
}
```

#### D. Server Broadcast Update (Server ➔ Other Clients)
Broadcasts incoming changes/tombstones to other devices:
```json
{
  "type": "clipboard_sync",
  "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
  "timestamp": "2026-06-14T14:18:00.000Z",
  "ciphertext": null,
  "nonce": null,
  "blob_version": 1,
  "is_deleted": true,
  "is_pinned": false
}
```

#### E. Heartbeat (Ping/Pong)
*   The server automatically pings if no frames are received for **45 seconds**: `{"type": "ping"}`
*   The client must reply within **10 seconds** with: `{"type": "pong"}`

#### F. Server Force Close Notification
If a device is deleted by another device via REST APIs:
1.  Server sends JSON frame: `{"type": "device_deleted", "message": "This device has been removed from your account"}`
2.  Server immediately closes connection with code `4003`.

#### G. Device Added Notification (Server ➔ Other Clients)
Pushed to other connected user devices when a new device is registered:
```json
{
  "type": "device_added",
  "device": {
    "device_id": "unique_device_id_string",
    "device_name": "My iPhone 15",
    "os": "iOS"
  }
}
```

#### H. Device Updated Notification (Server ➔ Other Clients)
Pushed to other connected user devices when an existing device updates its metadata (e.g. OS version during login or display name via PATCH):
```json
{
  "type": "device_updated",
  "device": {
    "device_id": "unique_device_id_string",
    "device_name": "My iPhone 15",
    "os": "iOS",
    "last_seen": "2026-08-30T12:00:00Z",
    "is_online": true,
    "push_enabled": true
  }
}
```

#### I. Clipboard Pin Notification (Server ➔ Other Clients)
Pushed to other connected user devices when a clipboard entry is pinned or unpinned via the lightweight pin toggle API:
```json
{
  "type": "clipboard_pin",
  "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
  "is_pinned": true,
  "pinned_at": "2026-08-30T14:18:00.000Z",
  "updated_at": "2026-08-30T14:18:00.000Z"
}
```

#### J. Username Updated Notification (Server ➔ Other Clients)
Pushed to other connected user devices when the user updates their profile username:
```json
{
  "type": "username_updated",
  "username": "NewUsername"
}
```

#### K. Email Updated Notification (Server ➔ Other Clients)
Pushed to other connected user devices when the user successfully changes their email address:
```json
{
  "type": "email_updated",
  "email": "new_email@example.com"
}
```

### WebSocket Close Status Codes

*   `1000`: Normal closure.
*   `1008`: Policy Violation (Insecure WebSocket connection rejected when `HTTPS_ONLY` is enabled, or authentication credentials invalid/blacklisted).
*   `4001`: Token Expired. Perform token refresh and reconnect.
*   `4002`: Ping/Pong Timeout. Reconnect (possible network drop).
*   `4003`: Device Deleted Remotely. Clear local state, logout user, redirect to login.
*   `1011`: Internal Server Error. Reconnect with exponential backoff.

---

## 5. REST API Reference

All protected API endpoints require an Authorization Header: `Authorization: Bearer <access_token>`.

### Authentication Endpoints

#### `GET /api/v1/auth/salt`
Retrieves KDF parameters to begin key derivation for login.
*   **Query Parameters:**
    *   `email` (string, required): The user's email address.
*   **Response (200 OK):**
    ```json
    {
      "salt": "dGhpcyBpcyBzYWx0...",
      "kdf_version": 1
    }
    ```
*   **Errors:**
    *   `404 Not Found`: Email not found (prevents email enumeration).
    *   `429 Too Many Requests`: Rate limit exceeded.

---

#### `POST /api/v1/register`
Registers a new user and registers the first device (Async).
> [!NOTE]
> On successful user and device registration, the server broadcasts a `"device_added"` event over WebSockets to any other connected devices for this user.
*   **Request Body:**
    ```json
    {
      "email": "user@example.com",
      "auth_key": "base64_encoded_client_derived_auth_key",
      "device_id": "unique_device_id_string",
      "device_name": "My iPhone 15",
      "os": "iOS",
      "encrypted_master_key": "base64_encoded_wrapped_key",
      "salt": "base64_encoded_salt",
      "kdf_version": 1
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "access_token": "eyJhbGciOi...",
      "refresh_token": "plain_refresh_token_string",
      "token_type": "bearer"
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: Validation failure (lengths out of bounds).
    *   `409 Conflict`: Email or Device ID already registered.

---

#### `POST /api/v1/login`
Logs in a user and registers/updates the device connection (Async).
> [!NOTE]
> * If a new device is auto-registered during login, a `"device_added"` event is broadcasted.
> * If an existing device updates its OS version during login, a `"device_updated"` event is broadcasted.
*   **Request Body:**
    ```json
    {
      "email": "user@example.com",
      "auth_key": "base64_encoded_client_derived_auth_key",
      "device_id": "unique_device_id_string",
      "device_name": "My iPhone 15",
      "os": "iOS"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "access_token": "eyJhbGciOi...",
      "refresh_token": "plain_refresh_token_string",
      "token_type": "bearer",
      "email": "user@example.com",
      "encrypted_master_key": "base64_encoded_wrapped_key",
      "salt": "base64_encoded_salt",
      "kdf_version": 1
    }
    ```
*   **Errors:**
    *   `401 Unauthorized`: Invalid credentials.
    *   `403 Forbidden`: Device ID belongs to another user.

---

#### `POST /api/v1/logout`
Logs out the current device and blacklists the current access token.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "refresh_token": "plain_refresh_token_string"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "message": "Logged out successfully"
    }
    ```

---

#### `POST /api/v1/refresh`
Obtains a new Access/Refresh token pair using Refresh Token Rotation (RTR).
*   **Request Body:**
    ```json
    {
      "refresh_token": "plain_refresh_token_string"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "access_token": "eyJhbGciOi...",
      "refresh_token": "new_plain_refresh_token_string",
      "token_type": "bearer"
    }
    ```
*   **Errors:**
    *   `401 Unauthorized`: Token expired, token invalid, or token reuse detected (triggers immediate revocation of the entire session family).

---

#### `POST /api/v1/password/change`
Changes the user password and updates the wrapped master key.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "old_auth_key": "base64_encoded_old_auth_key",
      "new_auth_key": "base64_encoded_new_auth_key",
      "new_encrypted_master_key": "base64_encoded_rewrapped_key",
      "new_salt": "base64_encoded_new_salt",
      "new_kdf_version": 1
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "message": "Password changed successfully. Master key re-wrapped."
    }
    ```
*   **Errors:**
    *   `401 Unauthorized`: Incorrect old auth key.

---

#### `GET /api/v1/user`
Retrieves safe profile information for the authenticated user (no passwords or private cryptographic keys).
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    {
      "user_id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
      "email": "user@example.com",
      "username": "Alice",
      "kdf_version": 1
    }
    ```

---

#### `PUT /api/v1/user/username`
Updates the friendly username for the authenticated user.
> [!NOTE]
> On successful update, the server broadcasts a `"username_updated"` event over WebSockets to all connected client devices for this user.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "username": "AliceSmith"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "message": "Username updated successfully",
      "username": "AliceSmith"
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: Username length out of bounds (1-128 characters).

---

#### `PUT /api/v1/user/email`
Updates the email address associated with the user account. Because tokens and KDF derivations may bind to email, this endpoint re-verifies the user's `auth_key` and issues a fresh token pair.
> [!NOTE]
> On successful update, the server broadcasts an `"email_updated"` event over WebSockets to all other connected client devices for this user.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "email": "new_email@example.com",
      "auth_key": "base64_encoded_current_auth_key"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "message": "Email updated successfully",
      "email": "new_email@example.com",
      "access_token": "eyJhbGciOi...",
      "refresh_token": "new_plain_refresh_token_string",
      "token_type": "bearer"
    }
    ```
*   **Errors:**
    *   `401 Unauthorized`: Invalid `auth_key`.
    *   `409 Conflict`: Email already in use by another account.

---

#### `DELETE /api/v1/delete`
Permanently deletes the user account, all device records, and all clipboard history.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    {
      "message": "Your account and all associated data have been deleted."
    }
    ```

---

### Device Management Endpoints

#### `POST /api/v1/devices/register`
Manually adds a new device connection to the user account (Async).
> [!NOTE]
> On successful registration, the server broadcasts a `"device_added"` event over WebSockets to any other connected devices for this user.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "device_id": "unique_device_id_string",
      "device_name": "My iPad Pro",
      "os": "iPadOS"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "device_id": "unique_device_id_string",
      "device_name": "My iPad Pro",
      "os": "iPadOS",
      "last_seen": "2026-08-30T12:00:00Z",
      "is_online": true,
      "push_enabled": false
    }
    ```
*   **Errors:**
    *   `403 Forbidden`: Device ID belongs to another user.

---

#### `GET /api/v1/devices`
Lists all active devices linked to the user account.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    [
      {
        "device_id": "unique_device_id_string",
        "device_name": "My iPad Pro",
        "os": "iPadOS",
        "last_seen": "2026-08-30T12:00:00Z",
        "is_online": true,
        "push_enabled": true
      }
    ]
    ```

---

#### `PUT /api/v1/devices/{device_id}/push`
Registers or updates a UnifiedPush webhook subscription URL for the device.
*   **Rate Limit:** 10 requests / minute
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body (`PushSubscription`):**
    ```json
    {
      "push_subscription": "https://ntfy.sh/up_synclo_unique_topic"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "device_id": "unique_device_id_string",
      "device_name": "My iPad Pro",
      "os": "iPadOS",
      "last_seen": "2026-08-30T12:00:00Z",
      "is_online": true,
      "push_enabled": true
    }
    ```
*   **Errors:**
    *   `404 Not Found`: Device not found under this user account.
    *   `422 Unprocessable Entity`: Invalid URL format or non-HTTPS URL in production.

---

#### `DELETE /api/v1/devices/{device_id}/push`
Removes the push notification subscription from the specified device.
*   **Rate Limit:** 10 requests / minute
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    {
      "device_id": "unique_device_id_string",
      "device_name": "My iPad Pro",
      "os": "iPadOS",
      "last_seen": "2026-08-30T12:00:00Z",
      "is_online": true,
      "push_enabled": false
    }
    ```
*   **Errors:**
    *   `404 Not Found`: Device not found under this user account.

---

#### `DELETE /api/v1/devices/{device_id}`
Removes a device, revokes its session tokens, and disconnects its active WebSocket.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    {
      "message": "Device 'My iPad Pro' deleted successfully"
    }
    ```
*   **Errors:**
    *   `404 Not Found`: Device not found under this user account.

---

#### `PATCH /api/v1/devices/{device_id}`
Updates the display name of an existing registered device.
> [!NOTE]
> On successful update, the server broadcasts a `"device_updated"` event over WebSockets to all other connected client devices for this user.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "device_name": "Work Laptop"
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "device_id": "unique_device_id_string",
      "device_name": "Work Laptop",
      "os": "Windows",
      "last_seen": "2026-06-14T14:18:00Z",
      "is_online": true
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: `device_name` length out of bounds (1-128 characters).
    *   `404 Not Found`: Device not found under this user account.

---

### Clipboard Endpoints

#### `POST /api/v1/clipboard`
Synchronizes or updates a clipboard item manually via REST.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
      "ciphertext": "base64_encoded_ciphertext",
      "nonce": "base64_encoded_nonce",
      "blob_version": 1,
      "timestamp": "2026-06-14T14:15:30Z",
      "is_pinned": false
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "status": "clipboard synced",
      "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9"
    }
    ```

---

#### `GET /api/v1/clipboard`
Fetches the latest active clipboard entry.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    {
      "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
      "ciphertext": "base64_encoded_ciphertext",
      "nonce": "base64_encoded_nonce",
      "blob_version": 1,
      "timestamp": "2026-06-14T14:15:30Z",
      "updated_at": "2026-06-14T14:15:31Z",
      "is_deleted": false,
      "deleted_at": null,
      "is_pinned": false
    }
    ```
*   **Errors:**
    *   `404 Not Found`: No clipboard entries found.

---

#### `GET /api/v1/clipboard/all`
Debug endpoint to retrieve all clipboard items.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Query Parameters:**
*   `include_deleted` (boolean, optional, default: `false`): Include deleted tombstones in response.
*   **Response (200 OK):**
    ```json
    [
      {
        "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
        "ciphertext": "base64_encoded_ciphertext",
        "nonce": "base64_encoded_nonce",
        "blob_version": 1,
        "timestamp": "2026-06-14T14:15:30Z",
        "updated_at": "2026-06-14T14:15:31Z",
        "is_deleted": false,
        "deleted_at": null,
        "is_pinned": false
      }
    ]
    ```

---

#### `GET /api/v1/clipboard/sync`
Delta sync endpoint for clients coming online to download changes.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Query Parameters:**
    *   `since` (ISO 8601 string, optional): Fetch updates modified after this server-time.
    *   `limit` (integer, optional, default: 1000): Pagination limit.
    *   `offset` (integer, optional, default: 0): Pagination offset.
*   **Response (200 OK):**
    ```json
    {
      "entries": [
        {
          "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
          "ciphertext": null,
          "nonce": null,
          "blob_version": 1,
          "timestamp": "2026-06-14T14:15:30Z",
          "updated_at": "2026-06-14T14:18:01Z",
          "is_deleted": true,
          "deleted_at": "2026-06-14T14:18:00Z",
          "is_pinned": false
        }
      ],
      "next_offset": 1,
      "has_more": false,
      "total_count": 1
    }
    ```
*   **Errors:**
    *   `410 Gone`: Triggered if the `since` timestamp is older than the `TOMBSTONE_RETENTION_DAYS` (30 days). The client must wipe its local cache and perform a full sync.

---

#### `GET /api/v1/clipboard/{clipboard_id}`
Retrieves a specific clipboard entry by its client-generated UUID.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    {
      "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
      "ciphertext": "base64_encoded_ciphertext",
      "nonce": "base64_encoded_nonce",
      "blob_version": 1,
      "timestamp": "2026-06-14T14:15:30Z",
      "updated_at": "2026-06-14T14:15:31Z",
      "is_deleted": false,
      "deleted_at": null,
      "is_pinned": true,
      "pinned_at": "2026-08-30T14:18:00Z"
    }
    ```
*   **Errors:**
    *   `404 Not Found`: Clipboard entry not found.

---

#### `PATCH /api/v1/clipboard/{clipboard_id}/pin`
Lightweight endpoint to toggle the pin status of an active clipboard item without re-transmitting or re-encrypting ciphertext payload blobs.
> [!NOTE]
> On successful update, the server broadcasts a lightweight `"clipboard_pin"` metadata event over WebSockets to all connected client devices for this user.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Request Body:**
    ```json
    {
      "is_pinned": true,
      "pinned_at": "2026-08-30T14:18:00Z"
    }
    ```
    *(If `pinned_at` is omitted when pinning, server defaults to the current UTC timestamp)*
*   **Response (200 OK):**
    ```json
    {
      "id": "c1f77d33-bc42-4916-b847-ec4b868e4bf9",
      "ciphertext": "base64_encoded_ciphertext",
      "nonce": "base64_encoded_nonce",
      "blob_version": 1,
      "timestamp": "2026-06-14T14:15:30Z",
      "updated_at": "2026-08-30T14:18:00Z",
      "is_deleted": false,
      "deleted_at": null,
      "is_pinned": true,
      "pinned_at": "2026-08-30T14:18:00Z"
    }
    ```
*   **Errors:**
    *   `400 Bad Request`: Cannot pin a deleted clipboard entry.
    *   `404 Not Found`: Clipboard entry not found.

---

#### `DELETE /api/v1/clipboard/{clipboard_id}`
Soft-deletes a single clipboard item (Idempotent).
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    {
      "message": "Clipboard entry deleted"
    }
    ```

---

#### `DELETE /api/v1/clipboard`
Soft-deletes all currently active, unpinned clipboard entries (history clearing). Pinned entries are preserved and skipped.
*   **Headers:** `Authorization: Bearer <access_token>`
*   **Response (200 OK):**
    ```json
    {
      "message": "15 clipboard entries deleted."
    }
    ```
    *(Returns `{"message": "No clipboard entries to delete."}` if history is already empty or only contains pinned items)*

---

#### `GET /api/health`
Public health status check. Used by client applications to verify server status and check that the target endpoint runs a genuine Synclo server.
*   **Response Headers:**
    *   `Synclo-Server`: `genuine` (used for client-side server identity verification)
*   **Response Body (200 OK):**
    ```json
    {
      "status": "ok",
      "server": "synclo"
    }
    ```

---

### System Policies & Transport Security

#### Transport Security & HTTPS Mode (`HTTPS_ONLY`)
To guarantee end-to-end transport security for tokens, payloads, and WebSockets in production, the server provides strict transport security controls configured via `HTTPS_ONLY` (boolean):

*   **HTTP-to-HTTPS Redirection:** When `HTTPS_ONLY=True`, non-HTTPS requests from remote hosts are redirected to `https://` with a `307 Temporary Redirect` status.
*   **HSTS Header:** Automatically attaches `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all HTTP responses.
*   **Reverse Proxy Support:** Detects TLS termination handled by reverse proxies (e.g. Nginx, Caddy, Cloudflare, Traefik) via the `X-Forwarded-Proto: https` header.
*   **Loopback Exemption:** Requests originating from loopback hosts (`localhost`, `127.0.0.1`, `::1`, `testserver`) bypass HTTPS redirection, allowing seamless local development and automated testing without SSL certificate setup.
*   **WebSocket WSS Enforcement:** Remote WebSocket upgrade requests over plain `ws://` without TLS are rejected with code `1008` (Policy Violation) and a descriptive error message.
*   **Push Distributor Validation:** Push subscription registration (`PUT /api/v1/devices/{device_id}/push`) validates distributor URLs and requires HTTPS when `HTTPS_ONLY=True` (allowing plain HTTP only on local loopback addresses).

---

#### Server-Wide Age-Based Clipboard Retention & Auto-Pruning (`CLIPBOARD_RETENTION_DAYS`)
The server enforces a server-wide retention policy for unpinned clipboard history, configured via `CLIPBOARD_RETENTION_DAYS` (default `30` days, `0` disables pruning):

*   **Expiration Rule:** Active unpinned clipboard items where `updated_at < (now - CLIPBOARD_RETENTION_DAYS)` are automatically expired.
*   **Pinning Immunity:** Pinned items (`is_pinned = True`) are completely immune to age-based pruning and are kept permanently until explicitly unpinned or deleted.
*   **Grace Period on Unpin:** Unpinning an item (`PATCH /api/v1/clipboard/{clipboard_id}/pin`) resets its `updated_at` timestamp to the current server time, granting a fresh 30-day retention window.
*   **Tombstone Generation & Broadcast:** Pruned items are soft-deleted (`is_deleted = True`, `ciphertext = None`, `nonce = None`, `deleted_at = now`) and broadcasted as `clipboard_sync` tombstone events over WebSockets to synchronize connected client devices.
*   **Trigger Points:** Pruning runs automatically during clipboard write operations (`POST /api/v1/clipboard`) and during periodic background maintenance (`run_all_cleanup`).

---

### Rate Limiting & API Safety

To protect the server from abuse, rate limits are applied to sensitive endpoints (e.g., registrations, logins, clipboard writes) using the `FastAPILimiter` middleware.

#### Expected Behavior on Limit Exceeded
When a client exceeds the request limit (typically 5 to 30 requests per minute depending on the endpoint), the server responds with:
*   **HTTP Status:** `429 Too Many Requests`
*   **Response Body (JSON):**
    ```json
    {
      "detail": "Rate limit exceeded"
    }
    ```

**Client Integration Best Practice:** Clients should implement a token bucket strategy or exponential backoff with jitter when encountering `429` statuses to avoid request thrashing and network bans.

---

## 6. Codebase Structure (File-by-File Analysis)

### Core Setup & Configurations (`app/core/`)

#### [config.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/core/config.py)
Loads environment configurations from `.env` files into a static `Settings` class. It performs startup security assertions, validating keys such as `SECRET_KEY`, `REFRESH_TOKEN_HASH_KEY`, `CLIPBOARD_RETENTION_DAYS`, and `HTTPS_ONLY`.

#### [constants.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/core/constants.py)
Defines project-wide size constraints (e.g. max ciphertext length of 64KB, salt lengths) and lists valid protocol and KDF versions.

#### [database.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/core/database.py)
Configures the SQLAlchemy engine and SQLite session pool, defining database connection options.

#### [logging_config.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/core/logging_config.py)
Initializes stdout stream loggers and rotating file log handlers writing logs to the `/app/logs/` folder.

#### [metrics.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/core/metrics.py)
Initializes Prometheus instrumentation middleware and exposes the `/metrics` endpoint with custom zero-knowledge metrics tracking active WebSockets, event dispatches, push notification latencies, and status outcomes.

---

### Database Models & Schemas

#### [models.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/models/models.py)
Declares database entities mapping users, devices, refresh tokens, blacklisted tokens, and clipboard tables.

#### [schemas.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/schemas/schemas.py)
Defines Pydantic v2 schemas used to filter and validate request JSON bodies, push URLs, and serialize responses.

---

### Core Business Logic (`app/services/`)

#### [auth.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/services/auth.py)
Coordinates JWT token encoding/decoding, password validation, and request authentication dependencies (`get_current_user`).

#### [crypto_utils.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/services/crypto_utils.py)
Calculates HMAC-SHA256 hashes of refresh tokens to secure database storage against key leakage.

#### [serializers.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/services/serializers.py)
Converts raw database byte fields (e.g., binary ciphertext, salt blobs) into base64-encoded strings for JSON serializations.

#### [utils.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/services/utils.py)
Defines scheduled database housekeeping routines: clearing revoked tokens, expired refresh sessions, old tombstone entries (`TOMBSTONE_RETENTION_DAYS`), and server-wide age-based clipboard history pruning (`CLIPBOARD_RETENTION_DAYS`).

#### [push_service.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/services/push_service.py)
Dispatches asynchronous zero-knowledge push notifications (`{"type": "push"}`) to UnifiedPush/FCM distributors with 5s timeout and automatic 400/404/410 stale subscription self-healing.

---

### API Routers & Endpoints (`app/endpoints/`)

#### [auth_endpoints.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/endpoints/auth_endpoints.py)
Processes accounts, sessions, password changes, token rotations, logouts, user deletions, profile retrievals, and username/email updates.

#### [device_endpoints.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/endpoints/device_endpoints.py)
Manages device list registries, device renaming, push subscription management, and remote device exclusions.

#### [clipboard_endpoints.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/endpoints/clipboard_endpoints.py)
Manages manual HTTP clipboard operations, delta updates, item pinning, history clears, and deletes.

#### [websocket_endpoints.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/endpoints/websocket_endpoints.py)
Handles client WebSocket upgrades (including TLS/WSS enforcement), heartbeat protocols, writes/deletes, asynchronous database saves via `asyncio.to_thread` pools, and broadcasts.

---

### WebSocket Connection Management

#### [connection_manager.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/websockets/connection_manager.py)
Monitors connection sockets in a thread-safe nested dictionary. Integrates Redis Pub/Sub channels to distribute broadcasts across clustered deployment nodes.

---

### Application Entry Point

#### [main.py](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/app/main.py)
Initializes the FastAPI application instance. Configures transport security middleware (`https_enforcement_middleware`), automatic migrations (`alembic upgrade head`), Redis connection pools, rate limits, Prometheus telemetry instrumentation (`/metrics`), periodic background cleanup loops, and global exception handlers.

## 7. Database Schema Reference

Synclo uses SQLite as its primary database. The schema is optimized for E2EE payloads, real-time device tracking, and delta-based synchronizations. Below is a detailed view of the tables and their relations:

```mermaid
erDiagram
    users {
        int id PK
        string user_id UK "UUID"
        string email UK
        string username
        string auth_key_hash
        binary encrypted_master_key
        binary salt
        int kdf_version
    }
    devices {
        int id PK
        string device_id UK
        string device_name
        string os
        string user_id FK "users.user_id"
        datetime last_seen
        string push_subscription
        datetime push_subscription_updated_at
    }
    clipboard {
        int id PK
        string clipboard_id UK
        string user_id FK "users.user_id"
        binary ciphertext
        binary nonce
        int blob_version
        datetime timestamp
        boolean is_deleted
        datetime deleted_at
        boolean is_pinned
        datetime pinned_at
        datetime updated_at
    }
    refresh_tokens {
        int id PK
        string user_id FK "users.user_id"
        string token UK
        datetime expiry
        string device_id
        string token_id "Rotation family ID"
        boolean is_revoked
    }
    blacklisted_tokens {
        int id PK
        string token UK
        datetime expiry
    }

    users ||--o{ devices : owns
    users ||--o{ clipboard : possesses
    users ||--o{ refresh_tokens : has
```

### Table Definitions

#### A. `users` Table
*   **`id`** (`Integer`, PK, Auto-increment): Database-internal primary identifier.
*   **`user_id`** (`String`, Unique, Index, Not Null): Public UUID string used as the primary identifier for database relationships and logs.
*   **`email`** (`String`, Unique, Index, Not Null): The user's registered email address.
*   **`username`** (`String`, Nullable): Friendly display name chosen by the user.
*   **`auth_key_hash`** (`String`, Not Null): Bcrypt hash of the HKDF client-derived auth key.
*   **`encrypted_master_key`** (`LargeBinary`, Not Null): Client-wrapped master decryption key (AES-256-GCM encrypted).
*   **`salt`** (`LargeBinary`, Not Null): 16-byte KDF salt used during password hashing.
*   **`kdf_version`** (`Integer`, Not Null, Default `1`): Argon2/PBKDF2 settings version.

#### B. `devices` Table
*   **`id`** (`Integer`, PK, Auto-increment): Database-internal primary identifier.
*   **`device_id`** (`String`, Unique, Index, Not Null): Client-generated unique device string.
*   **`device_name`** (`String`): Friendly name assigned to the device.
*   **`os`** (`String`, Nullable): Device OS metadata.
*   **`user_id`** (`String`, FK, Index): References `users.user_id` (UUID).
*   **`last_seen`** (`DateTime`, Index, Nullable): Timestamp of device's most recent activity.
*   **`push_subscription`** (`String`, Nullable): UnifiedPush webhook URL for background wake-ups.
*   **`push_subscription_updated_at`** (`DateTime`, Nullable): Timestamp when push subscription was registered or modified.

#### C. `clipboard` Table
*   **`id`** (`Integer`, PK, Auto-increment): Database-internal primary key (renamed from `index`).
*   **`clipboard_id`** (`String`, Unique, Index, Not Null): Client-generated item UUID (renamed from `id`).
*   **`user_id`** (`String`, FK): References `users.user_id` (UUID).
*   **`ciphertext`** (`LargeBinary`, Nullable): Encrypted clipboard content (purged/null when soft-deleted).
*   **`nonce`** (`LargeBinary`, Nullable): AES-GCM IV (purged/null when soft-deleted).
*   **`blob_version`** (`Integer`, Not Null, Default `1`): Encrypted payload structural schema version.
*   **`timestamp`** (`DateTime`): Client-side copying event timestamp.
*   **`is_deleted`** (`Boolean`, Index): Indicates if the item is a soft-deleted tombstone.
*   **`deleted_at`** (`DateTime`, Index, Nullable): Server timestamp of soft-deletion.
*   **`is_pinned`** (`Boolean`, Index, Not Null, Default `0`): Protects items from bulk clear operations and auto-pruning.
*   **`pinned_at`** (`DateTime`, Index, Nullable): Server timestamp when the item was pinned.
*   **`updated_at`** (`DateTime`, Index, Not Null): Server modification time used for offline client delta updates.

#### D. `refresh_tokens` Table
*   **`id`** (`Integer`, PK, Auto-increment): Database-internal primary identifier.
*   **`user_id`** (`String`, FK): References `users.user_id` (UUID).
*   **`token`** (`String`, Unique, Index): HMAC-SHA256 hash of the refresh token string.
*   **`expiry`** (`DateTime`, Index): Expiration timestamp.
*   **`device_id`** (`String`, Not Null): ID of the device associated with this session token.
*   **`token_id`** (`String`, Index, Not Null): Token family ID used for Rotation & Theft Detection (renamed from `family_id`).
*   **`is_revoked`** (`Boolean`, Default `False`): Tracks whether token has already been rotated.

#### E. `blacklisted_tokens` Table
*   **`id`** (`Integer`, PK, Auto-increment): Database-internal primary identifier.
*   **`token`** (`String`, Unique, Not Null): Invalidated access token value.
*   **`expiry`** (`DateTime`, Index, Not Null): Expiration time of token.

---

## 8. Database Schema Migration & Infrastructure

- **[alembic.ini](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/alembic.ini):** Configures Alembic migration routes.
- **[Dockerfile](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/Dockerfile):** Builds the standard Docker image using a `python:3.12-slim` base image.
- **[compose.yaml](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/compose.yaml):** Orchestrates multi-container runs (FastAPI App + Redis alpine instance) mapping storage folders to host paths.
- **[tests/](file:///E:/Files/Code-Stuff/Projects/Synclo-Backend/tests/):** Standardized pytest integration test suite targeting delta sync limits, device creation/revocation, pagination, pin toggles, and push services (executed via the `.venv` virtual environment).

---

## 9. Observability & Telemetry Subsystem

Synclo exposes operational metrics for real-time monitoring via Prometheus and Grafana scrapers at `GET /metrics`.

### Zero-Knowledge & Anonymity Guarantee
* **Strict Invariant**: Under no circumstances does the telemetry subsystem track or expose user-identifying data (PII, user IDs, usernames, email addresses, device IDs, IP addresses, session tokens, push distributor URLs, or ciphertext payloads).
* **Aggregation**: All telemetry is strictly aggregated at the server/instance level across anonymized dimensions (HTTP status codes, generic event types, and outcome statuses).

### Exposed Prometheus Metrics

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `http_requests_total` | Counter | `handler`, `method`, `status` | Total HTTP requests processed across API endpoints. |
| `http_request_duration_seconds` | Histogram | `handler`, `method` | HTTP request processing latency distribution. |
| `synclo_active_websockets` | Gauge | *None* | Current number of active local WebSocket client connections on the server node. |
| `synclo_websocket_events_total` | Counter | `event_type` | Total WebSocket messages broadcasted across the cluster, labeled only by generic event type (`clipboard_sync`, `clipboard_pin`, `device_updated`, `device_added`). |
| `synclo_push_dispatches_total` | Counter | `status` | Total background push notifications dispatched, labeled by outcome status (`success`, `stale_pruned`, `timeout`, `error`). |
| `synclo_push_duration_seconds` | Histogram | *None* | Latency of outbound push notification triggers to external distributor endpoints. |

