"""
db.py - MySQL Database Operations Module
Handles user credential storage and retrieval
"""

import mysql.connector
from mysql.connector import Error
from app.common.utils import constant_time_compare

DB_CONFIG = {
    'host': 'localhost',
    'user': 'securechat_user',
    'password': 'SecurePass123!',  
    'database': 'securechat'
}
def init_database():
    """
    Initialize database and create users table if not exists
    
    Returns:
        True if successful, False otherwise
    """
    try:
        # Connect without database first
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        cursor = conn.cursor()
        
        # Create database if not exists
        cursor.execute("CREATE DATABASE IF NOT EXISTS securechat")
        cursor.execute("USE securechat")
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                salt VARBINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_email (email),
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print("[+] Database initialized successfully")
        return True
        
    except Error as err:
        print(f"[!] Database error: {err}")
        return False

def get_db_connection():
    """
    Get database connection
    
    Returns:
        MySQL connection object
    """
    return mysql.connector.connect(**DB_CONFIG)

def register_user(email: str, username: str, salt: bytes, pwd_hash: str) -> tuple:
    """
    Register a new user in database
    
    Args:
        email: user email
        username: username
        salt: 16-byte random salt
        pwd_hash: hex string of SHA256(salt||password)
    
    Returns:
        (success: bool, message: str) tuple
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute(
            "SELECT * FROM users WHERE email = %s OR username = %s",
            (email, username)
        )
        
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return False, "User already exists"
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return True, "Registration successful"
        
    except Error as err:
        return False, f"Database error: {err}"

def get_user_salt(email: str) -> bytes:
    """
    Get salt for user by email
    
    Args:
        email: user email
    
    Returns:
        16-byte salt or None if user not found
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if result:
            return result[0]
        return None
        
    except Error as err:
        print(f"[!] Database error: {err}")
        return None

def verify_login(email: str, pwd_hash: str) -> tuple:
    """
    Verify user login credentials
    
    Args:
        email: user email
        pwd_hash: hex string of SHA256(salt||password)
    
    Returns:
        (success: bool, username: str or None, message: str) tuple
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT pwd_hash, username FROM users WHERE email = %s",
            (email,)
        )
        result = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if not result:
            return False, None, "User not found"
        
        stored_hash, username = result
        
        # Constant-time comparison to prevent timing attacks
        if constant_time_compare(pwd_hash, stored_hash):
            return True, username, "Login successful"
        else:
            return False, None, "Invalid password"
            
    except Error as err:
        return False, None, f"Database error: {err}"