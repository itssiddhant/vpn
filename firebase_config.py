import pyrebase
import hashlib
import random
import smtplib
from firebase_details import firebaseConfig

firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
db = firebase.database()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(email, password):
    hashed_password = hash_password(password)
    try:
        user = auth.create_user_with_email_and_password(email, hashed_password)
        db.child("users").push({"email": email, "password": hashed_password})
        print("User registered successfully")
    except Exception as e:
        print(f"Error registering user: {e}")

def login_user(email, password):
    hashed_password = hash_password(password)
    try:
        user = auth.sign_in_with_email_and_password(email, hashed_password)
        print("Login successful")
        return user['idToken']
    except Exception as e:
        print(f"Error logging in: {e}")
        return None



def send_otp(email):
    otp = random.randint(100000, 999999)
    db.child("otps").child(email.replace('.', ',')).set(otp)
    
    # Send OTP via email (using a service like SMTP)
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login("your-email@gmail.com", "your-password")
        message = f"Your OTP is {otp}"
        server.sendmail("your-email@gmail.com", email, message)
        server.quit()
        print("OTP sent successfully")
    except Exception as e:
        print(f"Error sending OTP: {e}")
    
def verify_otp(email, otp):
    stored_otp = db.child("otps").child(email.replace('.', ',')).get().val()
    if stored_otp == int(otp):
        print("OTP verified successfully")
        return True
    else:
        print("Invalid OTP")
        return False
