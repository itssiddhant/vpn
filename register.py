import pyrebase
import hashlib
from firebase_details import firebaseConfig

firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
db = firebase.database()
def hash_password(password):
    
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(email, password):
    """Registers a user with the given email and password."""
    hashed_password = hash_password(password)
    try:
        user = auth.create_user_with_email_and_password(email, hashed_password)
        db.child("users").push({"email": email, "password": hashed_password})
        print(f"User {email} registered successfully!")
    except Exception as e:
        print(f"Error registering user: {e}")

if __name__ == "__main__":
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    register_user(email, password)