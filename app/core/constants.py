import bcrypt

# Device constraints
MIN_DEVICE_ID_LEN = 3
MAX_DEVICE_ID_LEN = 128
MIN_DEVICE_NAME_LEN = 1
MAX_DEVICE_NAME_LEN = 128

# Key and salt constraints
MIN_AUTH_KEY_LEN = 16
MAX_AUTH_KEY_LEN = 256
MIN_SALT_LEN = 16
MAX_SALT_LEN = 256
MIN_MK_LEN = 16
MAX_MK_LEN = 8192
MIN_RECOVERY_KEY_VERIFIER_LEN = 16
MAX_RECOVERY_KEY_VERIFIER_LEN = 256

# Payload constraints
MAX_CIPHERTEXT_LEN = 65536
MAX_NONCE_LEN = 64
MIN_NONCE_LEN = 8

# Protocol versions
ALLOWED_BLOB_VERSIONS = {1}
ALLOWED_KDF_VERSIONS = {1}

# Network and proxy loopback hosts
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "testserver", "testclient"})

# WebSocket close codes
WS_CLOSE_NORMAL = 1000
WS_CLOSE_POLICY_VIOLATION = 1008
WS_CLOSE_INTERNAL_ERROR = 1011
WS_CLOSE_DEFAULT = 4000
WS_CLOSE_TOKEN_EXPIRED = 4001
WS_CLOSE_PING_TIMEOUT = 4002
WS_CLOSE_DEVICE_DELETED = 4003
WS_CLOSE_SESSION_INVALIDATED = 4004

# WebSocket intervals and timeouts
WS_PING_INTERVAL_SECONDS = 45
WS_PONG_TIMEOUT_SECONDS = 10
WS_LAST_SEEN_THROTTLE_SECONDS = 60.0

# Push service constraints
MAX_PUSH_RESPONSE_BYTES = 10 * 1024

# Pre-computed dummy bcrypt hash for constant-time authentication timing attack mitigation
DUMMY_BCRYPT_HASH = bcrypt.hashpw(b"timing_attack_mitigation_dummy_hash", bcrypt.gensalt()).decode("utf-8")
