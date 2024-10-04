from firebase_details import firebase_app, db, auth
import hashlib
import random
import smtplib
import time
from datetime import datetime
from cryptography.fernet import Fernet
import platform
import requests
from encdec import encrypt_message, decrypt_message


LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
ATTEMPT_PERIOD = 60 

def rate_limited_login(email):
    """Rate limits login attempts."""
    current_time = time.time()
    attempts = LOGIN_ATTEMPTS.get(email, [])
    
    # Remove attempts older than ATTEMPT_PERIOD
    attempts = [timestamp for timestamp in attempts if current_time - timestamp < ATTEMPT_PERIOD]
    LOGIN_ATTEMPTS[email] = attempts
    
    if len(attempts) >= MAX_ATTEMPTS:
        print("Too many login attempts. Please try again later.")
        return False
    
    # Record this attempt
    LOGIN_ATTEMPTS[email].append(current_time)
    return True


def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def login_user(email, password):
    if not rate_limited_login(email):
        return None, None

    try:
        user = auth.get_user_by_email(email)
        user_data = db.reference('users').child(user.uid).get()
        
        if user_data and user_data['password'] == hash_password(password):
            if user_data['role'].startswith('user-'):
                print("Login successful")
                return user.uid, user_data
            else:
                print("User not approved or invalid role")
        else:
            print("Invalid email or password")
        return None, None
    except Exception as e:
        print(f"Error logging in: {e}")
        return None, None

def record_login(user_id, email):
    login_data = {
        "device": platform.platform(),
        "timestamp": int(time.time())
    }
    db.reference('users').child(user_id).child("logins").push(login_data)
    
def fetch_email_credentials():
    try:
        users = db.reference('users').get()
        for user_id, user_data in users.items():
            email = user_data.get('email')
            app_password = user_data.get('app_password')  # Assuming you store app password separately
            if email and app_password:
                return email, app_password
        print("No email credentials found in the database.")
        return None, None
    except Exception as e:
        print(f"Error fetching email credentials: {e}")
        return None, None
    

def send_encrypted_message_to_server(message):
    try:
        encrypted_data = encrypt_message(message.encode())
        key, iv, encrypted_message = encrypted_data[:24], encrypted_data[24:32], encrypted_data[32:]
        
        # Send the encrypted message to the server using HTTPS
        response = requests.post('http://10.12.47.21:5000/receive_message', 
                                data=encrypted_message,
                                headers={'Content-Type': 'application/octet-stream',
                                       'Encryption-Key': key.hex(),
                                       'Encryption-IV': iv.hex()})
        
        if response.status_code == 200:
            print("Message sent and received successfully")
        else:
            print(f"Error sending message: {response.text}")
    except Exception as e:
        print(f"Error sending encrypted message to server: {e}")

