import pyotp
import base64
from config import TOTP_TIME_STEP, TOTP_VALID_WINDOW

class TOTPManager:
    """
    Manages Time-based One-Time Passwords (TOTP).
    """

    @staticmethod
    def generate_secret():
        """
        Generates a new random Base32 encoded TOTP secret.
        This secret is shared between the server and the user's authenticator app.
        """
        return pyotp.random_base32()

    @staticmethod
    def get_totp_code(secret):
        """
        Generates the current TOTP code based on the secret and current time.
        This is typically done on the client-side (authenticator app).
        """
        totp = pyotp.TOTP(secret, interval=TOTP_TIME_STEP)
        return totp.now()

    @staticmethod
    def verify_totp_code(secret, user_totp_code):
        """
        Verifies a user-provided TOTP code against the secret.
        This is done on the server-side.
        """
        totp = pyotp.TOTP(secret, interval=TOTP_TIME_STEP)
        # Verify with a time window to account for clock skew
        return totp.verify(user_totp_code, valid_window=TOTP_VALID_WINDOW)

    @staticmethod
    def get_provisioning_uri(username, secret, issuer_name="EmailServer"):
        """
        Generates a provisioning URI (e.g., for QR code generation).
        This URI can be used to set up authenticator apps like Google Authenticator.
        """
        return pyotp.TOTP(secret, interval=TOTP_TIME_STEP, name=username, issuer=issuer_name).provisioning_uri()

# Example Usage (for testing totp_manager independently)
if __name__ == '__main__':
    print("--- TOTP Manager Demonstration ---")

    # 1. Server generates a secret for a new user
    new_user_secret = TOTPManager.generate_secret()
    username = "demo_user"
    print(f"1. Server generates TOTP secret for '{username}': {new_user_secret}")

    # 2. Server provides provisioning URI to the user (e.g., via QR code)
    # The user would then scan this with their authenticator app.
    provisioning_uri = TOTPManager.get_provisioning_uri(username, new_user_secret)
    print(f"2. Provisioning URI for '{username}': {provisioning_uri}")
    print("   (Scan this URI with Google Authenticator or similar app)")

    # 3. User, using their authenticator app (or a client script), generates a TOTP code
    # We simulate this here
    current_totp_code = TOTPManager.get_totp_code(new_user_secret)
    print(f"\n3. Client (simulated authenticator app) generates current TOTP code: {current_totp_code}")

    # 4. Server verifies the user-provided TOTP code
    print(f"4. Server attempts to verify code '{current_totp_code}'...")
    if TOTPManager.verify_totp_code(new_user_secret, current_totp_code):
        print("   Verification successful!")
    else:
        print("   Verification failed.")

    # Simulate an incorrect code
    incorrect_code = "123456" # A random incorrect code
    print(f"\n5. Server attempts to verify an incorrect code '{incorrect_code}'...")
    if not TOTPManager.verify_totp_code(new_user_secret, incorrect_code):
        print("   Verification failed (correctly) for incorrect code.")
    else:
        print("   Verification succeeded (incorrectly) for incorrect code.")

    # Simulate a slightly old code (within valid_window)
    # To properly test valid_window, you'd need to mock time or wait.
    # For now, assume a real authenticator app would provide a valid code.
    print(f"\n6. If a code generated {TOTP_TIME_STEP * TOTP_VALID_WINDOW} seconds ago was provided, it would still pass.")
    print(f"   (This relies on the valid_window setting: current time step +/- {TOTP_VALID_WINDOW} steps)")