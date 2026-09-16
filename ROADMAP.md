# Synclo Backend — Strategic Roadmap (ROADMAP)

This document outlines the strategic engineering roadmap for the **Synclo Backend**, designed specifically for **Desktop (Windows, macOS, Linux)** and **Mobile (Android)** client ecosystems while preserving Synclo's core **Zero-Knowledge Architecture**.

---

## 🔮 Upcoming & Planned Features (Roadmap)

These capabilities are planned for upcoming minor and major milestones following the v1.0 foundational release.

### 1. Large Payload & Rich Media Sharing

#### ⏳ 1.1 Encrypted Image & File Sharing Pipeline — **[Planned]**
* **Status**: Planned
* **Why**: Expand beyond clipboard text to allow sharing screenshots, copied image files, documents, and binary attachments across devices.
* **Architecture**: 
  * Large binary payloads bypass the primary SQLite database and WebSocket frame stream.
  * Encrypted client-side with ephemeral symmetric file keys; uploaded to dedicated blob storage (S3-compatible or local object volume) using pre-signed, short-lived URLs.
  * Only metadata (content-type, size, ciphertext hash, nonce, blob reference) is broadcasted over WebSockets.
  * Automatic retention expiry for files (e.g., 7-day auto-purge).

---

### 2. Zero-Knowledge Security & Onboarding

#### ⏳ 2.1 OPAQUE Protocol Handshake (Asymmetric PAKE) — **[Planned]**
* **Status**: Planned
* **Why**: The current login flow requires an unauthenticated `GET /auth/salt` round-trip, exposing plaintext KDF salts and creating an email enumeration surface. Stolen server databases also remain subject to offline dictionary attacks against client auth keys.
* **Architecture**:
  * Implement the IETF OPAQUE protocol (RFC 9807), an Augmented Password-Authenticated Key Exchange (aPAKE).
  * Client blinds the password using an Oblivious Pseudorandom Function (OPRF); the server evaluates it with a server-side private key without ever learning the password or exposing cleartext salts.
  * Eliminates the `GET /api/v1/auth/salt` endpoint completely, cutting a full network round-trip from login flows and closing the salt-based user enumeration surface.
  * Encapsulates the user's Master Key within an encrypted credential envelope that cannot be brute-forced offline even if the database is leaked.

#### ⏳ 2.2 QR Code Device Pairing (Zero-Knowledge Key Handshake) — **[Planned]**
* **Status**: Planned
* **Why**: Typing long, high-entropy master passwords on mobile keyboards during device setup creates significant user friction.
* **Architecture**:
  * An authenticated desktop app generates an ephemeral session key and renders a QR code.
  * The mobile app scans the QR code and establishes a short-lived, encrypted end-to-end rendezvous channel (using Diffie-Hellman / P-256 key exchange) via the server to securely transfer the master key.

#### ⏳ 2.3 Two-Factor Authentication (TOTP) — **[Planned]**
* **Status**: Planned
* **Why**: Adds an extra authentication barrier on the server before issuing tokens or returning KDF salt/encrypted keys.
* **Architecture**:
  * Support RFC 6238 TOTP (Google Authenticator, Aegis, 1Password, etc.).
  * Enforce 2FA verification during login, password change, and account deletion.

---

### 3. Hardening & Operational Enhancements

#### ⏳ 3.1 Gated Prometheus Metrics Endpoint — **[Planned]**
* **Status**: Planned
* **Why**: The `/metrics` endpoint currently exposes operational metrics without authentication.
* **Architecture**: Restrict access to `/metrics` via HTTP Basic Auth, internal network / IP allowlisting, or toggle visibility behind `ENVIRONMENT != "production"`.

#### ⏳ 3.2 Opportunistic Blacklisted Token Pruning — **[Planned]**
* **Status**: Planned
* **Why**: The `blacklisted_tokens` table is currently pruned only once per 24 hours during `run_all_cleanup`.
* **Architecture**: Implement opportunistic pruning during user logout requests or shorten the periodic cleanup interval to reduce table size and indexing overhead.

---

## ✅ Completed & Implemented Features

The following core features establish the production-ready foundation for multi-device zero-knowledge synchronization.

### ✅ Mandatory Emergency Recovery Key Kit (Zero-Knowledge Account Recovery) — **[Implemented]**
* **Status**: Complete (`POST /api/v1/auth/recovery-material`, `POST /api/v1/auth/recover`, `POST /api/v1/auth/recovery-key/rotate`)
* **Why**: Under Zero-Knowledge encryption, forgetting the master password causes permanent data loss because the server cannot recover master keys. The Emergency Recovery Key Kit allows users to regain account access and retain existing encrypted history without external dependencies or cloud trust.
* **Architecture & Flow**:
  * **Zero-Knowledge Invariant**: The client generates a high-entropy 256-bit recovery key client-side. The raw recovery key never leaves the client device and is never sent to the server.
  * **Master Key Re-Wrapping**: Master Key ($MK$) is wrapped using $K_{rec} = \text{HKDF}(\text{Recovery Key}, \text{"recovery\_wrap"})$ producing `recovery_wrapped_master_key`.
  * **Verifier Authentication**: The client derives $V_{rec} = \text{HKDF}(\text{Recovery Key}, \text{"recovery\_verify"})$ which the server bcrypt-hashes and stores as `recovery_key_verifier`.
  * **Burn-on-Use Auto-Rotation**: During account recovery (`POST /api/v1/auth/recover`), the client derives and submits a brand-new recovery key kit, permanently burning and invalidating the used key.
  * **Session & Socket Invalidation**: Successful recovery revokes all existing refresh tokens and disconnects active WebSockets across all other devices with close code `4004` (Credentials Changed).
  * **Manual Rotation**: Logged-in users can rotate their recovery key at any time via `POST /api/v1/auth/recovery-key/rotate` or optionally during `POST /api/v1/password/change`.

### ✅ Dedicated Pin / Unpin Endpoint — **[Implemented]**
* **Status**: Complete (`PATCH /api/v1/clipboard/{id}/pin`)
* **Why**: Toggling a pin previously required re-transmitting the entire ciphertext/nonce payload or constructing a complete sync message.
* **Architecture & Flow**:
  * Lightweight endpoint accepting `{"is_pinned": bool, "pinned_at": Optional[datetime]}`.
  * Updates only metadata columns (`is_pinned`, `pinned_at`, `updated_at`) without modifying existing ciphertext or nonce blobs.
  * Broadcasts a lightweight metadata event over WebSockets (`{"type": "clipboard_pin", "id": ..., "is_pinned": ..., "pinned_at": ..., "updated_at": ...}`) so connected clients update their UI immediately without re-downloading or re-decrypting payload bytes.

---

### ✅ Device Renaming Endpoint — **[Implemented]**
* **Status**: Complete (`PATCH /api/v1/devices/{device_id}`)
* **Why**: Allows users to assign recognizable names to their devices (e.g., changing generic `"Windows"` to `"Workstation PC"`) directly from client settings.
* **Architecture & Flow**:
  * Accepts `{"device_name": "New Name"}` with validation against length boundaries.
  * Updates the `devices` table and broadcasts a `device_updated` WebSocket event (`{"type": "device_updated", "device": {...}}`) to keep device lists synchronized across all active client sessions.

---

### ✅ Server-Wide Age-Based Clipboard Retention & Auto-Pruning — **[Implemented]**
* **Status**: Complete (`CLIPBOARD_RETENTION_DAYS=30`, `prune_user_clipboard`, `prune_all_users_clipboard`)
* **Why**: Provides a predictable, natural clipboard retention model (e.g. 30 days of active history) without burdening clients with settings synchronization or storage management.
* **Architecture & Flow**:
  * **Server-Side Environment Configuration**: Configured via `CLIPBOARD_RETENTION_DAYS=30` (`0` = disabled / infinite retention).
  * **Universal Expiration Rule**: Unpinned entries are expired when `updated_at < (now - CLIPBOARD_RETENTION_DAYS)`.
  * **Unpin Grace Period**: Unpinning an item refreshes its `updated_at` timestamp, providing a fresh 30-day lifecycle from the moment it is unpinned.
  * **Auto-Pruning Invariants**:
    * **Pinned Items are Immune**: Pinned items (`is_pinned=True`) are exempt from age expiration and are kept permanently until explicitly unpinned or deleted.
    * **Tombstone Generation**: Pruned items are soft-deleted (`is_deleted=True`, `deleted_at=now`, `updated_at=now`, `ciphertext=None`, `nonce=None`) and broadcasted as standard `clipboard_sync` tombstones.
    * **Trigger Points**: Pruning triggers upon new clipboard additions, during client synchronization, and in scheduled maintenance routines (`run_all_cleanup`).

---

### ✅ Mobile Background Push Service (Unified Web Push / UnifiedPush) — **[Implemented]**
* **Status**: Complete (`PUT /api/v1/devices/{device_id}/push`, `DELETE /api/v1/devices/{device_id}/push`, `PushService`)
* **Why**: Mobile operating systems (Android, iOS) suspend background WebSocket connections to conserve battery. Without push notifications, mobile apps cannot wake up or pull sync events in the background.
* **Architecture & Flow**:
  * Stores device push subscription endpoint URLs (`push_subscription`) in the `devices` table with validation.
  * Dedicated non-blocking `PushService` using persistent `httpx.AsyncClient` connection pooling.
  * Automatically dispatches silent background wakeup pings to all registered background devices of a user whenever clipboard items are created, pinned, or deleted.
  * Automatic dead-endpoint pruning on `400`, `404`, or `410 Gone` HTTP distributor responses.

---

### ✅ Prometheus Metrics & Telemetry (`/metrics`) — **[Implemented]**
* **Status**: Complete (`GET /metrics`, `app.core.metrics`)
* **Why**: Real-time operational insight into HTTP throughput/latency, active WebSocket connections, Redis broadcast event counts, and background push notification delivery latencies across client devices.
* **Architecture & Flow**:
  * Exposes standard Prometheus text exposition format via `prometheus-fastapi-instrumentator` on `GET /metrics`.
  * **Zero-Knowledge & Privacy Guarantee**: Absolutely NO user-identifying data (user IDs, usernames, emails, device IDs, IP addresses, tokens, distributor URLs, or ciphertext payloads) is tracked or exposed.
  * **Custom Gauges & Counters**:
    * `synclo_active_websockets`: Real-time gauge of currently connected WebSocket client devices.
    * `synclo_websocket_events_total`: Event counter labeled strictly by generic event type (`clipboard_sync`, `clipboard_pin`, `device_updated`, `device_added`).
    * `synclo_push_dispatches_total`: Counter of push notification triggers labeled by outcome status (`success`, `stale_pruned`, `timeout`, `error`).
    * `synclo_push_duration_seconds`: Latency histogram tracking outbound HTTP push dispatch duration.

---

### ✅ HTTPS Mode & Transport Security (`HTTPS_ONLY`) — **[Implemented]**
* **Status**: Complete (`HTTPS_ONLY=True`, `https_enforcement_middleware`)
* **Why**: Ensures all in-transit clipboard payloads, session tokens, and authentication requests are strictly encrypted over TLS in production deployments.
* **Architecture & Flow**:
  * **Configurable Enforcement**: Configured via `HTTPS_ONLY` environment variable (`True` by default in production).
  * **Automated HTTP-to-HTTPS Redirection**: Non-HTTPS ingress HTTP requests receive a `307 Temporary Redirect` to their HTTPS counterpart.
  * **HSTS Injection**: Automatically injects `Strict-Transport-Security: max-age=31536000; includeSubDomains` header on all responses.
  * **Reverse Proxy Support**: Detects TLS termination at ingress proxies via standard `X-Forwarded-Proto: https` header.
  * **Loopback Development Exemption**: Local connections to `localhost`, `127.0.0.1`, `::1`, and `testserver` bypass redirection, simplifying local development and testing.
  * **WebSocket WSS Enforcement**: Insecure `ws://` WebSocket upgrade requests from remote clients are immediately rejected with close code `1008` (Policy Violation).
  * **Push Endpoint Validation**: Strict validation requiring HTTPS scheme for external push distributor URLs when `HTTPS_ONLY` is enabled.
