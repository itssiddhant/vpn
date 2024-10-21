from firebase_details import db, auth
import hashlib
import time
from datetime import datetime
import pytz 
import platform
import requests
from encdec import encrypt_message, decrypt_message
import os
from dotenv import load_dotenv
load_dotenv()


LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
ATTEMPT_PERIOD = 60 

def rate_limited_login(email):
    """Rate limits login attempts."""
    current_time = datetime.now(pytz.utc).isoformat()
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
        return None, None, None

    try:
        user = auth.get_user_by_email(email)
        user_data = db.reference('users').child(user.uid).get()

        if user_data and user_data['password'] == hash_password(password):
           if user_data['role'].startswith('user-'):
                print("Login successful")
                custom_token = auth.create_custom_token(user.uid)
                custom_token_str = custom_token.decode('utf-8')
                
                exchange_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={os.getenv('FIREBASE_API_KEY')}"
                response = requests.post(exchange_url, json={"token": custom_token_str, "returnSecureToken": True})
                if response.status_code == 200:
                    id_token = response.json()['idToken']
                    print(f"Authorization Token: {id_token}")  # For debugging
                    return user.uid, user_data, id_token
                else:
                    print("Error exchanging custom token for ID token")
           else:
                print("User not approved or invalid role")
        else:
            print("Invalid email or password")
        return None, None, None
    except Exception as e:
        print(f"Error logging in: {e}")
        return None, None, None

def record_login(user_id, email):
    time = datetime.now(pytz.utc)
    login_data = {
        "device": platform.platform(),
        "timestamp": time.isoformat()
    }
    db.reference('users').child(user_id).child("logins").push(login_data)
    
def fetch_email_credentials():
    try:
        users = db.reference('users').get()
        for user_id, user_data in users.items():
            email = user_data.get('email')
            app_password = user_data.get('app_password') 
            if email and app_password:
                return email, app_password
        print("No email credentials found in the database.")
        return None, None
    except Exception as e:
        print(f"Error fetching email credentials: {e}")
        return None, None
    

def send_encrypted_message_to_server(message,id_token):
    try:
        encrypted_data = encrypt_message(message.encode())
        key, iv, encrypted_message = encrypted_data[:24], encrypted_data[24:32], encrypted_data[32:]

        print(f"Toggling VPN with id_token: {id_token}") 
        # Send the encrypted message to the server using HTTPS
        response = requests.post('http://localhost:5000/receive_message', 
                                data=encrypted_message,
                                headers={'Content-Type': 'application/octet-stream',
                                       'Encryption-Key': key.hex(),
                                       'Encryption-IV': iv.hex(),
                                       'Authorization': f'Bearer {id_token}'})
        
        if response.status_code == 200:
            print("Message sent and received successfully")
        else:
            print(f"Error sending message: {response.text}")
    except Exception as e:
        print(f"Error sending encrypted message to server: {e}")

