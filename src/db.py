import sqlite3
import os
from config import DATABASE_NAME

class DatabaseManager:
    """
    Manages SQLite database connections and operations for user data.
    """
    def __init__(self, db_name=DATABASE_NAME):
        self.db_name = db_name
        self.create_table()

    def _get_connection(self):
        """Establishes and returns a database connection."""
        conn = sqlite3.connect(self.db_name)
        # Configure row_factory to return rows as dict-like objects
        conn.row_factory = sqlite3.Row
        return conn

    def create_table(self):
        """Creates the users table if it doesn't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    hashed_password BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    country TEXT NOT NULL,
                    city TEXT NOT NULL,
                    mobile_number TEXT,
                    totp_secret TEXT NOT NULL
                )
            ''')
            conn.commit()
        print(f"Database '{self.db_name}' and table 'users' ensured.")

    def add_user(self, username, hashed_password, salt, country, city, mobile_number, totp_secret):
        """Adds a new user to the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, hashed_password, salt, country, city, mobile_number, totp_secret)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (username, hashed_password, salt, country, city, mobile_number, totp_secret))
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            print(f"Error: User '{username}' already exists.")
            return False
        except Exception as e:
            print(f"Error adding user: {e}")
            return False

    def get_user(self, username):
        """Retrieves user information by username."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            return dict(user) if user else None

    def delete_user(self, username):
        """Deletes a user from the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE username = ?', (username,))
                conn.commit()
            if cursor.rowcount > 0:
                print(f"User '{username}' deleted successfully.")
                return True
            else:
                print(f"User '{username}' not found.")
                return False
        except Exception as e:
            print(f"Error deleting user: {e}")
            return False

# Example Usage (for testing the database module independently)
if __name__ == '__main__':
    
    # Clean up any existing database for fresh start
    if os.path.exists(DATABASE_NAME):
        os.remove(DATABASE_NAME)
        print(f"Removed existing {DATABASE_NAME}")

    db_manager = DatabaseManager()

    # Add a test user
    test_username = "testuser"
    test_hashed_password = b"dummy_hashed_password" # In real app, use crypto_utils
    test_salt = b"dummy_salt" # In real app, use crypto_utils
    test_country = "Brazil"
    test_city = "Florianopolis"
    test_mobile = "1234567890"
    test_totp_secret = "JBSWY3DPEHPK3PXP" # Base32 encoded secret

    print(f"Adding user {test_username}...")
    if db_manager.add_user(test_username, test_hashed_password, test_salt,
                            test_country, test_city, test_mobile, test_totp_secret):
        print("User added successfully.")
    else:
        print("Failed to add user.")

    # Try to add the same user again (should fail)
    print(f"Attempting to add user {test_username} again (should fail)...")
    if not db_manager.add_user(test_username, test_hashed_password, test_salt,
                                test_country, test_city, test_mobile, test_totp_secret):
        print("Duplicate user addition correctly prevented.")

    # Get user information
    print(f"\nRetrieving user {test_username}...")
    user_info = db_manager.get_user(test_username)
    if user_info:
        print("User found:")
        for key, value in user_info.items():
            # For demonstration, decode bytes to string for display if they are bytes
            if isinstance(value, bytes):
                print(f"  {key}: {value.hex()} (hex)")
            else:
                print(f"  {key}: {value}")
    else:
        print("User not found.")

    # Delete the test user
    print(f"\nDeleting user {test_username}...")
    if db_manager.delete_user(test_username):
        print("User deleted.")
    else:
        print("User not deleted (might not exist).")

    # Verify deletion
    print(f"\nVerifying deletion of user {test_username}...")
    user_info = db_manager.get_user(test_username)
    if not user_info:
        print("User successfully verified as deleted.")
    else:
        print("User still exists (deletion failed).")