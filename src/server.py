from flask import Flask, request, jsonify, session
import os
from db import DatabaseManager
from utils.crypto import CryptoUtils
from utils.ip import IPUtils
from totp import TOTPManager
from config import SERVER_URL

ALLOWED_COUNTRIES = ['LOCAL', 'BR'] 
ALLOWED_CITIES = ['LOCAL', 'FLORIANOPOLIS']

app = Flask(__name__)
app.secret_key = os.urandom(24)

db_manager = DatabaseManager()
ip_util = IPUtils()

ACTIVE_SESSION = {}


@app.route('/register', methods=['POST'])
def register_user():
    """
    Registers a new user.
    Requires: username, password, mobile_number (optional).
    Automatically detects IP location and generates TOTP secret.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    mobile_number = data.get('mobile_number')

    if not username or not password:
        return jsonify({"message": "Username and password are required."}), 400

    # Factor 1: Get IP Location
    client_ip = IPUtils.get_client_ip(request)
    location_info = ip_util.get_location_from_ip(client_ip)

    if not location_info:
        return jsonify({"message": "Could not determine IP location. Registration failed."}), 500

    user_country = location_info['country']
    user_city = location_info['city']

    # Generate salt for password hashing
    password_salt = CryptoUtils.generate_salt()
    hashed_password = CryptoUtils.hash_password(password, password_salt)

    # Generate TOTP secret
    totp_secret = TOTPManager.generate_secret()

    if db_manager.add_user(username, hashed_password, password_salt,
                            user_country, user_city, mobile_number, totp_secret):
        return jsonify({
            "message": "User registered successfully. Please add this secret to your authenticator app.",
            "username": username,
            "ip_location": f"{user_city}, {user_country}",
            "totp_secret": totp_secret,

        }), 201
    else:
        return jsonify({"message": "Registration failed. Username might already exist."}), 409

@app.route('/authenticate', methods=['POST'])
def authenticate_user():
    """
    Performs 3FA authentication for a user.
    Requires: username, password, totp_code.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    totp_code = data.get('totp_code')

    if not all([username, password, totp_code]):
        return jsonify({"message": "Username, password, and TOTP code are required for authentication."}), 400

    user_data = db_manager.get_user(username)

    if not user_data:
        return jsonify({"message": "Authentication failed: User not found."}), 401

    # --- Factor 1: IP Location Check ---
    client_ip = IPUtils.get_client_ip(request)
    current_location = ip_util.get_location_from_ip(client_ip)

    if not current_location:
        return jsonify({"message": "Authentication failed: Could not determine current IP location."}), 401

    if (current_location['country'] != user_data['country'] or
        current_location['city'] != user_data['city']):
        # Special handling for local IPs: if both are loopback, they match
        if (client_ip in ['127.0.0.1', '::1'] and user_data['country'].upper() in ALLOWED_COUNTRIES and user_data['city'].upper() in ALLOWED_CITIES):
            print(f"IP Factor: Matched local IP for {username}.")
        else:
            return jsonify({
                "message": f"Authentication failed: IP location mismatch. "
                           f"Registered: {user_data['city']}, {user_data['country']}. "
                           f"Current: {current_location['city']}, {current_location['country']}."
            }), 401
    print(f"IP Factor: User '{username}' authenticated from correct location.")

    # --- Factor 2: Password Verification ---
    if not CryptoUtils.verify_password(password, user_data['salt'], user_data['hashed_password']):
        return jsonify({"message": "Authentication failed: Incorrect username or password."}), 401
    print(f"Password Factor: User '{username}' provided correct password.")

    # --- Factor 3: TOTP Verification ---
    if not TOTPManager.verify_totp_code(user_data['totp_secret'], totp_code):
        return jsonify({"message": "Authentication failed: Invalid TOTP code."}), 401
    print(f"TOTP Factor: User '{username}' provided valid TOTP code.")

    
    # Generate a salt for key derivation for this *specific session*.
    # This salt is NOT stored; it's used for this session's key derivation only.
    session_kdf_salt = CryptoUtils.generate_salt(length=16) # Use a good length for KDF salt
    
    # The derived key is based on the TOTP secret AND a fresh session salt.
    # This makes the derived key unique to each authentication instance, even if the TOTP secret is static.
    session_symmetric_key = CryptoUtils.derive_symmetric_key(
        user_data['totp_secret'].encode('utf-8'), # TOTP secret as bytes
        session_kdf_salt
    )

    # All 3 factors passed. User is authenticated.
    ACTIVE_SESSION.update({
        "username": username,
        "key": session_symmetric_key,
        "kdf_salt": session_kdf_salt
    })
    
    return jsonify({
        "message": "Authentication successful! You can now send encrypted messages.",
        "username": username,
        "session_kdf_salt": session_kdf_salt.hex(), # Send the KDF salt to client for their key derivation
        "user_totp_secret": user_data['totp_secret'], # Send the KDF salt to client for their key derivation
    }), 200

@app.route('/send_message', methods=['POST'])
def send_message():
    """
    Receives an encrypted message from an authenticated user and decrypts it.
    Requires: username, iv, ciphertext, tag, associated_data.
    """
    data = request.get_json()
    username = data.get('username')
    if username != ACTIVE_SESSION["username"]:
        print("Unauthorized access attempt. No active session.")
        return jsonify({"message": "Unauthorized. Please authenticate first."}), 401
    
    # Retrieve the session key for this authenticated user
    if not ACTIVE_SESSION or not ACTIVE_SESSION.get("key"):
        return jsonify({"message": "Session key not found. Please re-authenticate."}), 401

    derived_key = ACTIVE_SESSION["key"]

    data = request.get_json()
    iv_hex = data.get('iv')
    ciphertext_hex = data.get('ciphertext')
    tag_hex = data.get('tag')
    associated_data_str = data.get('associated_data') # Can be None

    if not all([iv_hex, ciphertext_hex, tag_hex]):
        return jsonify({"message": "Missing encrypted message components (IV, ciphertext, tag)."}), 400

    try:
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        tag = bytes.fromhex(tag_hex)
        associated_data = associated_data_str.encode('utf-8') if associated_data_str else None
    except ValueError:
        return jsonify({"message": "Invalid hexadecimal encoding for cryptographic components."}), 400

    decrypted_message = CryptoUtils.decrypt_message(derived_key, iv, ciphertext, tag, associated_data)

    if decrypted_message is None:
        return jsonify({"message": "Message decryption failed (authentication tag mismatch or corrupted data)."}), 403
    else:
        print(f"Decrypted message successfully: '{decrypted_message.decode('utf-8')}'")
        return jsonify({
            "message": "Message received and decrypted successfully!",
            "decrypted_content": decrypted_message.decode('utf-8'),
            "sender": username
        }), 200

@app.route('/logout', methods=['POST'])
def logout_user():
    """Logs out the user by clearing the session."""
    username = session.pop('username', None)
    if username and username in ACTIVE_SESSION:
        del ACTIVE_SESSION[username]
        return jsonify({"message": f"User '{username}' logged out successfully."}), 200
    return jsonify({"message": "No active session to log out."}), 200


if __name__ == '__main__':
    # Ensure the database is initialized
    db_manager.create_table()
    print("Server starting on http://127.0.0.1:5001")
    print("WARNING: Flask development server is not suitable for production environments.")
    app.run(debug=True, host='0.0.0.0', port=SERVER_URL.split(':')[-1]) # Extract port from SERVER_URL