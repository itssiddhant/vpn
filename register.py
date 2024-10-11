from firebase_details import  auth, db
import hashlib
import random
import time
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import os
from dotenv import load_dotenv
load_dotenv()

# In-memory OTP storage
otp_storage = defaultdict(dict)

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = os.getenv("SENDER_MAIL_ADDRESS")  
SENDER_PASSWORD = os.getenv("SENDER_APP_PASSWORD") 

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_valid_email(email):
    email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
    return email_regex.match(email)

def is_strong_password(password):
    # Password should be at least 8 characters long and contain at least one uppercase letter,
    # one lowercase letter, one digit, and one special character
    password_regex = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$")
    return password_regex.match(password)

def send_email(to_email, subject, body):
    try:
        message = MIMEMultipart()
        message["From"] = SENDER_EMAIL
        message["To"] = to_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(message)
        print(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_otp(email):
    if not is_valid_email(email):
        print("Invalid email format")
        return False

    otp = str(random.randint(100000, 999999))
    otp_storage[email] = {"otp": otp, "timestamp": int(time.time())}
    
    subject = "Password Reset OTP"
    body = f"Your OTP for password reset is: {otp}\nThis OTP is valid for 5 minutes."
    
    if send_email(email, subject, body):
        return True
    return False

def verify_otp(email, otp_input):
    stored_otp = otp_storage.get(email)
    if stored_otp and stored_otp['otp'] == otp_input:
        current_time = int(time.time())
        if current_time - stored_otp['timestamp'] <= 300:  # OTP valid for 5 minutes
            del otp_storage[email]  # Remove OTP after verification
            return True
    return False

def register_user(email, password, organization):
    if not is_valid_email(email):
        print("Invalid email format")
        return False

    if not is_strong_password(password):
        print("Password is not strong enough")
        return False

    hashed_password = hash_password(password)
    try:
        user = auth.create_user(
            email=email,
            password=password
        )
        db.reference('users').child(user.uid).set({
            "email": email,
            "password": hashed_password,
            "role": f"none-{organization}",
            "organization": organization
        })
        db.reference('pending_approvals').child(organization).push({
            "user_id": user.uid,
            "email": email,
            "organization": organization
        })
        print(f"User {email} registered successfully!")
        return True
    except Exception as e:
        print(f"Error registering user: {e}")
        return False