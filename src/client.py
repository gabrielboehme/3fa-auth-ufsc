import requests
import pyotp
from utils.crypto import CryptoUtils
from config import SERVER_URL

# --- Configuration ---


# --- Global variables for client session ---
# In a real app, these would be managed securely (e.g., encrypted local storage, secure element)
# For this academic project, they are in-memory.
SESSION = {
    'username': None,
    'derived_key': None
}


def register():
    """Handles user registration."""
    global client_totp_secret
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
            client_totp_secret = data.get('totp_secret')
            print(f"Your TOTP Secret: {client_totp_secret}")
            print("\nPlease add this TOTP Secret to your authenticator app (e.g., Google Authenticator).")
            print("It's crucial for the third authentication factor!\n")
        else:
            print(f"Error registering: {data.get('message', 'Unknown error')}")
    except requests.exceptions.ConnectionError:
        print("Could not connect to the server. Is it running?")
    except Exception as e:
        print(f"An error occurred while registering user: {e}")
        raise e

def authenticate():
    """Handles 3FA authentication."""
    print("\n--- User Authentication (3FA) ---")
    username = input("Enter username: ")
    password = input("Enter password: ")
    # Get TOTP code from user (assuming they have it in an authenticator app)
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
            client_kdf_salt = data.get('session_kdf_salt')
            if client_kdf_salt:
                # Client derives the symmetric key using the same secret and salt as the server
                # In a real scenario, the client would have stored their TOTP secret securely.
                # For this academic project, we use client_totp_secret if it was obtained from registration.
                client_totp_secret = data.get('user_totp_secret')
                if client_totp_secret:
                    client_derived_key = CryptoUtils.derive_symmetric_key(
                        client_totp_secret.encode('utf-8'),
                        bytes.fromhex(client_kdf_salt)
                    )
                    SESSION['username'] = data.get("username")
                    SESSION['derived_key'] = client_derived_key
                else:
                    raise ValueError("Warning: client_totp_secret not available. Cannot derive session key on client.")
            else:
                print("Error: Server did not provide session KDF salt.")
        else:
            print(f"Authentication failed: {data.get('message', 'Unknown error')}")
    except requests.exceptions.ConnectionError:
        print("Could not connect to the server. Is it running?")
    except Exception as e:
        print(f"An error occurred while athenticating the user: {e}")
        raise e

def send_encrypted_message():
    """Sends an encrypted message to the server."""
    print("\n--- Send Encrypted Message ---")
    if not SESSION.get("username") or not SESSION.get("derived_key"):
        print("You must authenticate before sending messages.")
        return
    
    message = input("Enter message to encrypt and send: ")
    
    # Associated Data: Authenticate the sender's username
    associated_data = SESSION["username"].encode('utf-8')

    # Encrypt the message using the derived session key
    iv, ciphertext, tag = CryptoUtils.encrypt_message(SESSION["derived_key"], message.encode('utf-8'), associated_data)



    payload = {
        "username": SESSION["username"], # Send username for server context
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
        print(f"An error occurred while sending message: {e}")
        raise e

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