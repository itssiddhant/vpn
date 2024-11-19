import os
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from firebase_details import firebase_app, auth, db
from encdec import decrypt_message
import platform
from datetime import datetime
import logging

app = Flask(__name__)

# Set up rate limiting
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)
# Set up logging
logging.basicConfig(level=logging.INFO)

@app.route('/receive_message', methods=['GET'])
@limiter.limit("50/minute")  # Adjust rate limit for this endpoint
def receive_message():
    try:
        # Verify Firebase ID token
        id_token = request.headers.get('Authorization')
        if id_token and id_token.startswith("Bearer "):
            id_token = id_token.split("Bearer ")[1]
        else:
            return jsonify({"status": "error", "message": "Invalid or missing authorization token"}), 401

        app.logger.info(f"Received token: {id_token}")

        try:
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            app.logger.info(f"Token claims: {decoded_token}")
        except auth.ExpiredIdTokenError:
            return jsonify({"status": "error", "message": "Token expired"}), 401
        except auth.RevokedIdTokenError:
            return jsonify({"status": "error", "message": "Token revoked"}), 401
        except auth.InvalidIdTokenError:
            return jsonify({"status": "error", "message": "Invalid token"}), 401
        except auth.FirebaseError as e:
            return jsonify({"status": "error", "message": f"Token verification failed: {str(e)}"}), 401

        
        encrypted_message = request.data
        if not encrypted_message:
            return jsonify({"status": "error", "message": "No encrypted message provided"}), 400

        # Handle missing headers gracefully
        encryption_key_hex = request.headers.get('Encryption-Key')
        encryption_iv_hex = request.headers.get('Encryption-IV')
        algo = request.headers.get('Encryption-Algorithm', 'AES')  # Defaults to AES if not specified
        
        if not encryption_key_hex or not encryption_iv_hex:
            return jsonify({"status": "error", "message": "Encryption key or IV missing"}), 400
        
        try:
            encryption_key = bytes.fromhex(encryption_key_hex)
            encryption_iv = bytes.fromhex(encryption_iv_hex)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid encryption key or IV format"}), 400
        
        algoCodes = {'AES': b'a', 'Blowfish': b'b', 'ChaCha20': b'c'}
        if algo not in algoCodes:
            return jsonify({
                "status": "error", 
                "message": f"Unsupported encryption algorithm: {algo}"
            }), 400
        
        full_encrypted_data = algoCodes[algo] + encryption_key + encryption_iv + encrypted_message
        decrypted_message = decrypt_message(full_encrypted_data)
        
        # Process the decrypted message here
        app.logger.info(f"Received and decrypted message from user {uid}: {decrypted_message}...")  # Log only a preview
        
        return jsonify({"status": "success", "message": "Message received and decrypted"}), 200
    except Exception as e:
        app.logger.error(f"Error in receive_message: {str(e)}")
        return jsonify({"status": "error", "message": "An error occurred processing the message"}), 400

@app.route('/record_login', methods=['POST'])
@limiter.limit("20/minute")  # Adjust rate limit for login recording
def record_login():
    try:
        # Verify Firebase ID token
        id_token = request.headers.get('Authorization')
        if not id_token:
            return jsonify({"status": "error", "message": "No authorization token provided"}), 401
        
        try:
            # Verify the ID token
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
        except auth.ExpiredIdTokenError:
            return jsonify({"status": "error", "message": "Token expired"}), 401
        except auth.InvalidIdTokenError:
            return jsonify({"status": "error", "message": "Invalid token"}), 401
        except Exception as e:
            return jsonify({"status": "error", "message": f"Token verification failed: {str(e)}"}), 401
        
        login_data = {
            "device": platform.platform(),
            "timestamp": datetime.now().isoformat()
        }
        
        # Record the login data in Firebase
        db.reference('users').child(uid).child("logins").push(login_data)
        
        app.logger.info(f"Login recorded for user {uid} at {login_data['timestamp']}")
        
        return jsonify({"status": "success", "message": "Login recorded successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error in record_login: {str(e)}")
        return jsonify({"status": "error", "message": "An error occurred recording the login"}), 400
     
if __name__ == '__main__':
    app.run(host='localhost', port=5000)
