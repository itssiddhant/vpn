from firebase_details import credentials, auth, db
import hashlib
import random
import time
from collections import defaultdict

# In-memory OTP storage
otp_storage = defaultdict(dict)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_otp(email):
    otp = str(random.randint(100000, 999999))
    otp_storage[email] = {"otp": otp, "timestamp": int(time.time())}
    print(f"OTP for {email}: {otp}")  # For testing purposes
    # TODO: Implement actual email sending logic here

def verify_otp(email, otp_input):
    stored_otp = otp_storage.get(email)
    if stored_otp and stored_otp['otp'] == otp_input:
        current_time = int(time.time())
        if current_time - stored_otp['timestamp'] <= 300:  # OTP valid for 5 minutes
            del otp_storage[email]  # Remove OTP after verification
            return True
    return False


def register_user(email, password, organization):
    hashed_password = hash_password(password)
    try:
        user = auth.create_user(
            email=email,
            password=password
        )
        db.reference('users').child(user.uid).set({
            "email": email,
            "password": hashed_password,  # Store hashed password
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