import firebase_admin
from firebase_admin import credentials, auth, db
import os
from dotenv import load_dotenv
load_dotenv()

def initialize_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate("firebase_key.json")
        firebase_admin.initialize_app(cred, {
            'databaseURL': os.getenv("FIREBASE_DATABASEURL")
        })

    return firebase_admin.get_app()

# Initialize Firebase
firebase_app = initialize_firebase()