import os
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from firebase_details import firebase_app, auth, db
from encdec import decrypt_message
import platform
from datetime import datetime
import logging
from urllib.parse import urlparse, urljoin
import requests
from flask import Response, stream_with_context

app = Flask(__name__)

# Set up rate limiting
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)
# Set up logging
logging.basicConfig(level=logging.INFO)

def validate_url(url):
    """Validate and normalize the target URL."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = 'https://' + url
        return url
    except Exception as e:
        logging.error(f"URL validation error: {e}")
        return None

# Add these new routes to the existing Flask app
@app.route('/proxy/<path:url>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@limiter.limit("100/minute")
def proxy(url):
    try:
        # Get auth token from query parameters
        auth_token = request.args.get('auth_token')
        if not auth_token:
            return jsonify({
                "status": "error",
                "message": "Missing auth_token parameter"
            }), 401

        try:
            # Verify Firebase token
            decoded_token = auth.verify_id_token(auth_token)
            uid = decoded_token['uid']
            logging.info(f"Authenticated request from user {uid}")
        except Exception as e:
            logging.error(f"Token verification failed: {e}")
            return jsonify({
                "status": "error",
                "message": "Invalid authentication token"
            }), 401

        # Validate and normalize the URL
        target_url = validate_url(url)
        if not target_url:
            return jsonify({
                "status": "error",
                "message": "Invalid URL"
            }), 400

        # Prepare headers - forward original headers but remove problematic ones
        headers = {
            key: value for key, value in request.headers.items()
            if key.lower() not in {
                'host', 'content-length', 'connection', 
                'authorization', 'content-encoding'
            }
        }
        
        # Add custom headers to identify proxy requests
        headers.update({
            'X-Forwarded-For': request.remote_addr,
            'X-Forwarded-Proto': request.scheme,
            'X-Forwarded-Host': request.host,
            'User-Agent': 'Custom-VPN-Proxy/1.0'
        })

        # Make the proxied request
        try:
            resp = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=request.get_data(),
                params={k: v for k, v in request.args.items() if k != 'auth_token'},
                stream=True,
                timeout=30,
                allow_redirects=True,
                verify=True  # Enable SSL verification
            )
        except requests.RequestException as e:
            logging.error(f"Proxy request failed: {e}")
            return jsonify({
                "status": "error",
                "message": f"Failed to reach target server: {str(e)}"
            }), 502

        # Create and return streaming response
        excluded_headers = {
            'content-encoding', 'content-length', 'transfer-encoding', 'connection'
        }
        headers = [
            (k, v) for k, v in resp.raw.headers.items()
            if k.lower() not in excluded_headers
        ]

        return Response(
            stream_with_context(resp.iter_content(chunk_size=1024)),
            status=resp.status_code,
            headers=headers,
            content_type=resp.headers.get('content-type')
        )

    except Exception as e:
        logging.error(f"Proxy error: {e}")
        return jsonify({
            "status": "error",
            "message": "Internal proxy error"
        }), 500

@app.route('/receive_message', methods=['POST'])
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

# check VPN status
@app.route('/vpn/status', methods=['GET'])
def check_vpn_status():
    try:
        auth_token = request.headers.get('Authorization')
        if not auth_token or not auth_token.startswith("Bearer "):
            return jsonify({"status": "error", "message": "Invalid token"}), 401
            
        decoded_token = auth.verify_id_token(auth_token.split("Bearer ")[1])
        return jsonify({
            "status": "success",
            "connected": True,
            "user_id": decoded_token['uid']
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
}),500

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
    app.run(
        host='0.0.0.0',  # Bind to all interfaces
        port=5000,        # Standard HTTPS port
        debug=False      # Disable debug mode in production
    )
