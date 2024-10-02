import socket
import pyrebase
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

def get_device_info():
    """Gets the device information (hostname and platform details)."""
    device_info = {
        "hostname": socket.gethostname(),
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "platform": platform.system(),
        "platform_version": platform.version()
    }
    return device_info

def log_login_attempt(email, device_info):
    """Logs the login time and device information in Firebase."""
    login_data = {
        "email": email,
        "login_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "device_info": device_info
    }
    try:
        db.child("login_logs").push(login_data)
        print("Login attempt logged successfully.")
    except Exception as e:
        print(f"Error logging login attempt: {e}")
        
def login_user(email, password):
    """Logs in the user with Firebase authentication."""
    if not rate_limited_login(email):
        return None
    
    hashed_password = hash_password(password)
    try:
        user = auth.sign_in_with_email_and_password(email, hashed_password)
        print("Login successful")
        device_info = get_device_info()
        
        log_login_attempt(email, device_info)
        return user['idToken']
    except Exception as e:
        print(f"Error logging in: {e}")
        return None

def fetch_email_credentials():
    """Fetches the email and password for sending OTP from Firebase database."""
    try:
        users = db.child("users").get().val()
        for user_id, user_data in users.items():
            email = user_data['email']
            app_password = user_data['password']
            # Return the email and app password
            return email, app_password
        print("No email credentials found in the database.")
        return None, None
    except Exception as e:
        print(f"Error fetching email credentials: {e}")
        return None, None
    
def send_otp(email, recipient_email,password):
    """Generates and sends an OTP to the user's email."""
    otp = random.randint(100000, 999999)
    db.child("otps").child(recipient_email.replace('.', ',')).set(otp)
    print(email+password)
    # Send OTP via email (using SMTP)
    print(otp)
    try:
        
        if email and password:
            server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
            server.login(email, password)  # Use fetched credentials
            message = f"Your OTP is {otp}"
            server.sendmail(email, recipient_email, message)
            server.quit()
            print("OTP sent successfully")
        else:
            print("Failed to send OTP due to missing email credentials.")
    except Exception as e:
        print(f"Error sending OTP: {e}")


def verify_otp(email, otp):
    """Verifies the OTP entered by the user."""
    stored_otp = db.child("otps").child(email.replace('.', ',')).get().val()
    if stored_otp == int(otp):
        print("OTP verified successfully")
        return True
    else:
        print("Invalid OTP")
        return False

def send_encrypted_message_to_server(message):
    try:
        encrypted_data = encrypt_message(message.encode())
        key, iv, encrypted_message = encrypted_data[:24], encrypted_data[24:32], encrypted_data[32:]
        
        # Send the encrypted message to the server using HTTPS
        # response = requests.post('https://your-server-domain.com/receive_message', 
        #                          data=encrypted_message,
        #                          headers={'Content-Type': 'application/octet-stream',
        #                                   'Encryption-Key': key.hex(),
        #                                   'Encryption-IV': iv.hex()})
        
        if response.status_code == 200:
            print("Message sent and received successfully")
        else:
            print(f"Error sending message: {response.text}")
    except Exception as e:
        print(f"Error sending encrypted message to server: {e}")

