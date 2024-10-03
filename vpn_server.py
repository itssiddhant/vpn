import os
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyrebase
from firebase_details import firebaseConfig
from encdec import decrypt_message
import platform
from datetime import datetime

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address)

# Initialize Firebase
firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()
db = firebase.database()

@app.route('/receive_message', methods=['POST'])
@limiter.limit("10/minute")  # Adjust rate limit as needed
def receive_message():
    try:
        # Verify Firebase ID token
        id_token = request.headers.get('Authorization')
        if not id_token:
            return jsonify({"status": "error", "message": "No authorization token provided"}), 401
        
        try:
            user = auth.get_account_info(id_token)
            uid = user['users'][0]['localId']
        except Exception as e:
            return jsonify({"status": "error", "message": "Invalid authorization token"}), 401
        
        encrypted_message = request.data
        encryption_key = bytes.fromhex(request.headers.get('Encryption-Key'))
        encryption_iv = bytes.fromhex(request.headers.get('Encryption-IV'))
        
        if not encryption_key or not encryption_iv:
            return jsonify({"status": "error", "message": "Encryption key or IV missing"}), 400
        
        full_encrypted_data = encryption_key + encryption_iv + encrypted_message
        decrypted_message = decrypt_message(full_encrypted_data).decode()
        
        # Process the decrypted message here
        # For now, we'll just print it, but you might want to store it or perform other actions
        app.logger.info(f"Received and decrypted message from user {uid}: {decrypted_message}")
        
        return jsonify({"status": "success", "message": "Message received and decrypted"}), 200
    except Exception as e:
        app.logger.error(f"Error in receive_message: {str(e)}")
        return jsonify({"status": "error", "message": "An error occurred processing the message"}), 400

@app.route('/record_login', methods=['POST'])
def record_login():
    try:
        # Verify Firebase ID token
        id_token = request.headers.get('Authorization')
        if not id_token:
            return jsonify({"status": "error", "message": "No authorization token provided"}), 401
        
        try:
            user = auth.get_account_info(id_token)
            uid = user['users'][0]['localId']
        except Exception as e:
            return jsonify({"status": "error", "message": "Invalid authorization token"}), 401
        
        login_data = {
            "device": platform.platform(),
            "timestamp": datetime.now().isoformat()
        }
        
        # Record the login data in Firebase
        db.child("users").child(uid).child("logins").push(login_data)
        
        return jsonify({"status": "success", "message": "Login recorded successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error in record_login: {str(e)}")
        return jsonify({"status": "error", "message": "An error occurred recording the login"}), 400