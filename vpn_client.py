import socket
import hashlib
import random
import smtplib
import time
import socket
import pyrebase
import hashlib
import random
import smtplib
import time
from datetime import datetime
from cryptography.fernet import Fernet
import platform
from firebase_details import firebaseConfig
import requests
from encdec import encrypt_message, decrypt_message


firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
db = firebase.database()

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
    hashed_password = hash_password(password)
    try:
        user = auth.sign_in_with_email_and_password(email, hashed_password)
        user_data = db.child("users").child(user['localId']).get().val()
        if user_data and user_data['role'].startswith('user-'):
            print("Login successful")
            return user['idToken'], user_data
        else:
            print("User not approved or invalid role")
            return None, None
    except Exception as e:
        print(f"Error logging in: {e}")
        return None, None

def record_login(user_id, email):
    login_data = {
        "device": platform.platform(),
        "timestamp": int(time.time())
    }
    db.child("users").child(user_id).child("logins").push(login_data)
    
def fetch_email_credentials():
    """Fetches the email and password for sending OTP from Firebase database."""
    try:
        users = db.child("users").get().val()
        for user_data in users.items():
            email = user_data['email']
            app_password = user_data['password']
            # Return the email and app password
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
        response = requests.post('https://your-server-domain.com/receive_message', 
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

