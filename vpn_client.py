import socket
import pyrebase
import hashlib
import random
import smtplib
import time
from firebase_details import firebaseConfig

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
    """Logs in the user with Firebase authentication."""
    if not rate_limited_login(email):
        return None
    
    hashed_password = hash_password(password)
    try:
        user = auth.sign_in_with_email_and_password(email, hashed_password)
        print("Login successful")
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

def send_encrypted_message_to_server(encrypted_message):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        client_socket.sendall(encrypted_message)
        client_socket.close()
    except Exception as e:
        print(f"Error sending encrypted message to server: {e}")

