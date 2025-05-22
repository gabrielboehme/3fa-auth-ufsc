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
