import requests
import pyotp
import os
import base64
from utils.crypto import CryptoUtils
from config import AES_KEY_LENGTH, GCM_IV_LENGTH, SCRYPT_DKLEN_KDF

# --- Configuration ---
SERVER_URL = "http://127.0.0.1:5000"

# --- Global variables for client session ---
# In a real app, these would be managed securely (e.g., encrypted local storage, secure element)
# For this academic project, they are in-memory.
CLIENT_TOTP_SECRET = None
CLIENT_SESSION_KEY = None
CLIENT_KDF_SALT = None # The salt received from the server for symmetric key derivation
AUTHENTICATED_USERNAME = None


def register():
    """Handles user registration."""
    global CLIENT_TOTP_SECRET
    print("\n--- User Registration ---")
    username = input("Enter desired username: ")
    password = input("Enter password: ")
    mobile_number = input("Enter mobile number (optional): ")

    payload = {
        "username": username,
        "password": password,
        "mobile_number": mobile_number if mobile_number else None
    }

    try:
        response = requests.post(f"{SERVER_URL}/register", json=payload)
        data = response.json()
        print(f"Server response: {data.get('message')}")
        if response.status_code == 201:
            CLIENT_TOTP_SECRET = data.get('totp_secret')
            print(f"Your TOTP Secret: {CLIENT_TOTP_SECRET}")
            print(f"Provisioning URI: {data.get('provisioning_uri')}")
            print("\nPlease add this TOTP Secret to your authenticator app (e.g., Google Authenticator).")
            print("It's crucial for the third authentication factor!")
        else:
            print(f"Error registering: {data.get('message', 'Unknown error')}")
    except requests.exceptions.ConnectionError:
        print("Could not connect to the server. Is it running?")
    except Exception as e:
        print(f"An error occurred: {e}")

def authenticate():
    """Handles 3FA authentication."""
    global CLIENT_SESSION_KEY, CLIENT_KDF_SALT, AUTHENTICATED_USERNAME
    print("\n--- User Authentication (3FA) ---")
    username = input("Enter username: ")
    password = input("Enter password: ")

    # Get TOTP code from user (assuming they have it in an authenticator app)
    if CLIENT_TOTP_SECRET:
        print(f"Generating TOTP code using your secret '{CLIENT_TOTP_SECRET}'...")
        totp_code = pyotp.TOTP(CLIENT_TOTP_SECRET).now()
        print(f"Generated TOTP Code (client-side): {totp_code}")
    else:
        totp_code = input("Enter TOTP code from your authenticator app: ")

    payload = {
        "username": username,
        "password": password,
        "totp_code": totp_code
    }

    try:
        response = requests.post(f"{SERVER_URL}/authenticate", json=payload)
        data = response.json()
        print(f"Server response: {data.get('message')}")
        if response.status_code == 200:
            AUTHENTICATED_USERNAME = username
            CLIENT_KDF_SALT = data.get('session_kdf_salt')
            if CLIENT_KDF_SALT:
                # Client derives the symmetric key using the same secret and salt as the server
                # In a real scenario, the client would have stored their TOTP secret securely.
                # For this academic project, we use CLIENT_TOTP_SECRET if it was obtained from registration.
                if CLIENT_TOTP_SECRET:
                    client_derived_key = CryptoUtils.derive_symmetric_key(
                        CLIENT_TOTP_SECRET.encode('utf-8'),
                        bytes.fromhex(CLIENT_KDF_SALT)
                    )
                    CLIENT_SESSION_KEY = client_derived_key
                    print(f"Client successfully derived session key: {CLIENT_SESSION_KEY.hex()}")
                else:
                    print("Warning: CLIENT_TOTP_SECRET not available. Cannot derive session key on client.")
            else:
                print("Error: Server did not provide session KDF salt.")
        else:
            print(f"Authentication failed: {data.get('message', 'Unknown error')}")
    except requests.exceptions.ConnectionError:
        print("Could not connect to the server. Is it running?")
    except Exception as e:
        print(f"An error occurred: {e}")

def send_encrypted_message():
    """Sends an encrypted message to the server."""
    print("\n--- Send Encrypted Message ---")
    if not AUTHENTICATED_USERNAME or not CLIENT_SESSION_KEY:
        print("You must authenticate first to send an encrypted message.")
        return

    message = input("Enter message to encrypt and send: ")
    
    # Associated Data: Authenticate the sender's username
    associated_data = AUTHENTICATED_USERNAME.encode('utf-8')

    # Encrypt the message using the derived session key
    iv, ciphertext, tag = CryptoUtils.encrypt_message(CLIENT_SESSION_KEY, message.encode('utf-8'), associated_data)

    payload = {
        "username": AUTHENTICATED_USERNAME, # Send username for server context
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
        "associated_data": associated_data.decode('utf-8') # Send AAD as string
    }

    try:
        response = requests.post(f"{SERVER_URL}/send_message", json=payload)
        data = response.json()
        print(f"Server response: {data.get('message')}")
        if response.status_code == 200:
            print(f"Decrypted content from server: '{data.get('decrypted_content')}'")
            print(f"Sender confirmed by server: '{data.get('sender')}'")
        else:
            print(f"Failed to send/decrypt message on server: {data.get('message', 'Unknown error')}")
    except requests.exceptions.ConnectionError:
        print("Could not connect to the server. Is it running?")
    except Exception as e:
        print(f"An error occurred: {e}")

def logout():
    """Logs out the user."""
    global CLIENT_TOTP_SECRET, CLIENT_SESSION_KEY, CLIENT_KDF_SALT, AUTHENTICATED_USERNAME
    try:
        response = requests.post(f"{SERVER_URL}/logout")
        data = response.json()
        print(f"Server response: {data.get('message')}")
        if response.status_code == 200:
            CLIENT_TOTP_SECRET = None
            CLIENT_SESSION_KEY = None
            CLIENT_KDF_SALT = None
            AUTHENTICATED_USERNAME = None
            print("Client-side session cleared.")
    except requests.exceptions.ConnectionError:
        print("Could not connect to the server. Is it running?")
    except Exception as e:
        print(f"An error occurred: {e}")


def main_menu():
    """Displays the main menu and handles user choices."""
    while True:
        print("\n--- 3FA Authentication System Client ---")
        print("1. Register User")
        print("2. Authenticate User (3FA)")
        print("3. Send Encrypted Message")
        print("4. Logout")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            register()
        elif choice == '2':
            authenticate()
        elif choice == '3':
            send_encrypted_message()
        elif choice == '4':
            logout()
        elif choice == '5':
            print("Exiting client. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main_menu()