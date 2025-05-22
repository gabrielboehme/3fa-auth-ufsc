# --- Database Configuration ---
DATABASE_NAME = 'auth_system.db'
SERVER_URL = "http://127.0.0.1:5001"

# --- SCRYPT Parameters for Password Hashing ---
# N: CPU/memory cost parameter
# r: block size parameter
# p: parallelization parameter
# Derived key length
SCRYPT_N_PASSWORD = 2**10
SCRYPT_R_PASSWORD = 8
SCRYPT_P_PASSWORD = 1
SCRYPT_DKLEN_PASSWORD = 32 # 256 bits

# --- SCRYPT Parameters for Key Derivation (from TOTP secret) ---
# N: CPU/memory cost parameter
# r: block size parameter
# p: parallelization parameter
# Derived key length for AES-256
SCRYPT_N_KDF = 2**14
SCRYPT_R_KDF = 8
SCRYPT_P_KDF = 1
SCRYPT_DKLEN_KDF = 32 # 256 bits for AES-256

# --- TOTP Configuration ---
# Time step for TOTP in seconds
TOTP_TIME_STEP = 30
# Number of allowed time steps for validation
TOTP_VALID_WINDOW = 1

# --- AES-GCM Configuration ---
# AES key length in bytes
AES_KEY_LENGTH = 32
# GCM IV length in bytes
GCM_IV_LENGTH = 12