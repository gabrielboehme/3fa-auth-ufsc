# --- Database Configuration ---
DATABASE_NAME = 'auth_system.db'
SERVER_URL = "http://127.0.0.1:5001"

# --- SCRYPT Parameters for Password Hashing (OWASP recommended) ---
# N: CPU/memory cost parameter (2^17)
# r: block size parameter (8)
# p: parallelization parameter (1)
# Derived key length (e.g., 32 bytes for a strong hash)
SCRYPT_N_PASSWORD = 2**17
SCRYPT_R_PASSWORD = 8
SCRYPT_P_PASSWORD = 1
SCRYPT_DKLEN_PASSWORD = 32 # 256 bits

# --- SCRYPT Parameters for Key Derivation (from TOTP secret) ---
# N: CPU/memory cost parameter (2^14 for interactive logins)
# r: block size parameter (8)
# p: parallelization parameter (1)
# Derived key length for AES-256 (32 bytes)
SCRYPT_N_KDF = 2**14
SCRYPT_R_KDF = 8
SCRYPT_P_KDF = 1
SCRYPT_DKLEN_KDF = 32 # 256 bits for AES-256

# --- TOTP Configuration ---
# Time step for TOTP in seconds
TOTP_TIME_STEP = 30
# Number of allowed time steps for validation (e.g., 1 allows current and 1 before/after)
TOTP_VALID_WINDOW = 1

# --- AES-GCM Configuration ---
# AES key length in bytes (256 bits)
AES_KEY_LENGTH = 32
# GCM IV length in bytes (96 bits recommended)
GCM_IV_LENGTH = 12