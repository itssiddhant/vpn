from firebase_details import db, auth
import hashlib
import time
from datetime import datetime,timedelta
import pytz 
import platform
import requests
from encdec import encrypt_message, decrypt_message
import os
from dotenv import load_dotenv
load_dotenv()
import webbrowser

def open_through_vpn(url, id_token):
    """Opens a website through the VPN server."""
    try:
        proxy_url = f"http://192.168.0.165:5000/proxy/{url}"
        auth_url = f"{proxy_url}?auth_token={id_token}"
        
        # Use a new thread to open the browser
        webbrowser.open_new_tab(auth_url)
        return True
    except Exception as e:
        print(f"Error opening website through VPN: {e}")
        return False


LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
ATTEMPT_PERIOD = 60 

def rate_limited_login(email):
    """Rate limits login attempts."""
    current_time = datetime.now(pytz.utc)
    attempts = LOGIN_ATTEMPTS.get(email, [])
    
    # Remove attempts older than ATTEMPT_PERIOD
    cutoff_time = current_time - timedelta(seconds=ATTEMPT_PERIOD)
    attempts = [timestamp for timestamp in attempts 
               if datetime.fromisoformat(timestamp) > cutoff_time]
    LOGIN_ATTEMPTS[email] = attempts
    
    if len(attempts) >= MAX_ATTEMPTS:
        print("Too many login attempts. Please try again later.")
        return False
    
    # Record this attempt
    LOGIN_ATTEMPTS[email].append(current_time.isoformat())
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
           if user_data['role'].startswith('user-') | user_data['role'].startswith('admin-'):
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

def fetch_login_details(user_id):
    try:
        logins = db.reference('users').child(user_id).child('logins').order_by_child('timestamp').limit_to_last(3).get()

        last_login_details = []
        if logins:
            for login_data in reversed(list(logins.values())):
                login_time = datetime.fromisoformat(login_data['timestamp'])
                login_time_local = login_time.astimezone(pytz.timezone('Asia/Kolkata'))
                last_login_details.append(login_time_local.strftime('%Y-%m-%d %H:%M:%S'))
        else:
            last_login_details = ['No login data available']

        return last_login_details
    except Exception as e:
        print(f"Error fetching login details: {e}")
        return None

def send_encrypted_message_to_server(message,id_token, algo='AES'):
    try:
        encrypted_data = encrypt_message(message, algo)
        algoCode = encrypted_data[0:1].decode()

        if algoCode == 'a':  # AES
            key = encrypted_data[1:33]
            iv = encrypted_data[33:49]
            encrypted_message = encrypted_data[49:]
        elif algoCode == 'b':  # Blowfish
            key = encrypted_data[1:57]
            iv = encrypted_data[57:65]
            encrypted_message = encrypted_data[65:]
        elif algoCode == 'c':  # ChaCha20
            key = encrypted_data[1:33]
            iv = encrypted_data[33:49]
            encrypted_message = encrypted_data[49:]
        else:
            raise ValueError("Invalid algorithm code")

        print(f"Toggling VPN with id_token: {id_token}") 

        # Send the encrypted message to the server using HTTPS
        response = requests.post('http://192.168.0.165:5000/receive_message', 
                                data=encrypted_message,
                                headers={'Content-Type': 'application/octet-stream',
                                       'Encryption-Key': key.hex(),
                                       'Encryption-IV': iv.hex(),
                                       'Encryption-Algorithm': algo,
                                       'Authorization': f'Bearer {id_token}'})
        
        if response.status_code == 200:
            print("Message sent and received successfully")
            return True
        else:
            print(f"Error sending message: {response.text}")
            return False
    except Exception as e:
        print(f"Error sending encrypted message to server: {e}")
        return False

