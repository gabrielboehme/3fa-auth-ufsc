import os
import hashlib
import hmac
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