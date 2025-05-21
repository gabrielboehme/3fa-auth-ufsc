import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from config import (
    SCRYPT_N_PASSWORD, SCRYPT_R_PASSWORD, SCRYPT_P_PASSWORD, SCRYPT_DKLEN_PASSWORD,
    SCRYPT_N_KDF, SCRYPT_R_KDF, SCRYPT_P_KDF, SCRYPT_DKLEN_KDF,
    AES_KEY_LENGTH, GCM_IV_LENGTH
)

class CryptoUtils:
    """
    Provides cryptographic utilities for password hashing, key derivation,
    and authenticated symmetric encryption (AES-GCM).
    """

    @staticmethod
    def generate_salt(length=16):
        """Generates a random salt."""
        return os.urandom(length)

    @staticmethod
    def hash_password(password, salt):
        """
        Hashes a password using SCRYPT.
        Returns the hashed password bytes.
        """
        if not isinstance(password, bytes):
            password = password.encode('utf-8')
        if not isinstance(salt, bytes):
            raise TypeError("Salt must be bytes.")

        # Using hashlib.scrypt for password hashing as it's built-in and secure
        hashed_password = hashlib.scrypt(
            password,
            salt=salt,
            n=SCRYPT_N_PASSWORD,
            r=SCRYPT_R_PASSWORD,
            p=SCRYPT_P_PASSWORD,
            dklen=SCRYPT_DKLEN_PASSWORD
        )
        return hashed_password

    @staticmethod
    def verify_password(password, salt, stored_hash):
        """
        Verifies a password against a stored hash using SCRYPT.
        Returns True if passwords match, False otherwise.
        """
        if not isinstance(password, bytes):
            password = password.encode('utf-8')
        if not isinstance(salt, bytes) or not isinstance(stored_hash, bytes):
            raise TypeError("Salt and stored_hash must be bytes.")

        recalculated_hash = hashlib.scrypt(
            password,
            salt=salt,
            n=SCRYPT_N_PASSWORD,
            r=SCRYPT_R_PASSWORD,
            p=SCRYPT_P_PASSWORD,
            dklen=SCRYPT_DKLEN_PASSWORD
        )
        # Use hmac.compare_digest for constant-time comparison to prevent timing attacks
        return hmac.compare_digest(recalculated_hash, stored_hash)

    @staticmethod
    def derive_symmetric_key(secret_material, salt):
        """
        Derives a symmetric key using SCRYPT Key Derivation Function (KDF).
        The secret_material could be the TOTP secret.
        """
        if not isinstance(secret_material, bytes):
            secret_material = secret_material.encode('utf-8')
        if not isinstance(salt, bytes):
            raise TypeError("Salt must be bytes.")

        kdf = Scrypt(
            salt=salt,
            length=SCRYPT_DKLEN_KDF,
            n=SCRYPT_N_KDF,
            r=SCRYPT_R_KDF,
            p=SCRYPT_P_KDF,
            backend=default_backend()
        )
        derived_key = kdf.derive(secret_material)
        return derived_key

    @staticmethod
    def encrypt_message(key, plaintext, associated_data=None):
        """
        Encrypts a plaintext message using AES-256 in GCM mode.
        Returns (iv, ciphertext, tag).
        associated_data is authenticated but not encrypted.
        """
        if not isinstance(key, bytes) or len(key) != AES_KEY_LENGTH:
            raise ValueError(f"Key must be {AES_KEY_LENGTH} bytes.")
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8')
        if associated_data and not isinstance(associated_data, bytes):
            associated_data = associated_data.encode('utf-8')

        # GCM recommends 96-bit (12-byte) IV for efficiency
        iv = os.urandom(GCM_IV_LENGTH)
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        return iv, ciphertext, tag

    @staticmethod
    def decrypt_message(key, iv, ciphertext, tag, associated_data=None):
        """
        Decrypts an AES-GCM encrypted message.
        Raises InvalidTag if authentication fails.
        """
        if not isinstance(key, bytes) or len(key) != AES_KEY_LENGTH:
            raise ValueError(f"Key must be {AES_KEY_LENGTH} bytes.")
        if not isinstance(iv, bytes) or len(iv) != GCM_IV_LENGTH:
            raise ValueError(f"IV must be {GCM_IV_LENGTH} bytes.")
        if not isinstance(ciphertext, bytes) or not isinstance(tag, bytes):
            raise TypeError("Ciphertext and tag must be bytes.")
        if associated_data and not isinstance(associated_data, bytes):
            associated_data = associated_data.encode('utf-8')

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except InvalidTag:
            print("Authentication failed during decryption. Message may be tampered or key/IV/tag is incorrect.")
            return None
        except Exception as e:
            print(f"Error during decryption: {e}")
            return None

# Example Usage (for testing crypto_utils independently)
if __name__ == '__main__':
    import hmac # Imported here for the example for verify_password

    # --- Password Hashing and Verification ---
    print("\n--- Password Hashing and Verification ---")
    password = "MySecurePassword123!"
    salt_password = CryptoUtils.generate_salt()
    print(f"Generated salt for password: {salt_password.hex()}")

    hashed_pw = CryptoUtils.hash_password(password, salt_password)
    print(f"Hashed password: {hashed_pw.hex()}")

    if CryptoUtils.verify_password(password, salt_password, hashed_pw):
        print("Password verification successful!")
    else:
        print("Password verification failed.")

    # Test with incorrect password
    if not CryptoUtils.verify_password("WrongPassword", salt_password, hashed_pw):
        print("Incorrect password correctly failed verification.")
    else:
        print("Incorrect password incorrectly succeeded verification.")

    # --- Symmetric Key Derivation ---
    print("\n--- Symmetric Key Derivation ---")
    totp_secret_str = "JBSWY3DPEHPK3PXP" # Example Base32 TOTP secret
    totp_secret_bytes = totp_secret_str.encode('ascii') # Encode to bytes for KDF
    salt_kdf = CryptoUtils.generate_salt()
    print(f"TOTP Secret (Base32): {totp_secret_str}")
    print(f"Generated salt for KDF: {salt_kdf.hex()}")

    derived_key = CryptoUtils.derive_symmetric_key(totp_secret_bytes, salt_kdf)
    print(f"Derived symmetric key ({len(derived_key)} bytes): {derived_key.hex()}")

    # --- AES-GCM Encryption and Decryption ---
    print("\n--- AES-GCM Encryption and Decryption ---")
    message = "This is a super secret message for the server!"
    associated_data = "user:testuser_id:123" # Example AAD

    # Using the derived_key for encryption
    iv, ciphertext, tag = CryptoUtils.encrypt_message(derived_key, message.encode('utf-8'), associated_data.encode('utf-8'))
    print(f"Original message: '{message}'")
    print(f"Associated Data: '{associated_data}'")
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Tag: {tag.hex()}")

    decrypted_message = CryptoUtils.decrypt_message(derived_key, iv, ciphertext, tag, associated_data.encode('utf-8'))
    if decrypted_message:
        print(f"Decrypted message: '{decrypted_message.decode('utf-8')}'")
        assert decrypted_message.decode('utf-8') == message
        print("Decryption successful and message matches original.")

    # Test decryption with tampered ciphertext (should fail authentication)
    print("\n--- Testing AES-GCM with Tampered Ciphertext ---")
    tampered_ciphertext = ciphertext[:-2] + b'\x00\x01' # Tamper last two bytes
    print(f"Tampered Ciphertext: {tampered_ciphertext.hex()}")
    decrypted_tampered = CryptoUtils.decrypt_message(derived_key, iv, tampered_ciphertext, tag, associated_data.encode('utf-8'))
    if decrypted_tampered is None:
        print("Tampered ciphertext correctly failed decryption/authentication.")

    # Test decryption with wrong key (should fail authentication)
    print("\n--- Testing AES-GCM with Wrong Key ---")
    wrong_key = os.urandom(AES_KEY_LENGTH) # A completely different key
    decrypted_wrong_key = CryptoUtils.decrypt_message(wrong_key, iv, ciphertext, tag, associated_data.encode('utf-8'))
    if decrypted_wrong_key is None:
        print("Decryption with wrong key correctly failed.")