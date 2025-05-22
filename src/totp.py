import pyotp
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
