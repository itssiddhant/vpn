import os
import socket
import ssl
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
from encdec import decrypt_message

app = Flask(__name__)

@app.route('/receive_message', methods=['POST'])
def receive_message():
    try:
        encrypted_message = request.data
        encryption_key = bytes.fromhex(request.headers.get('Encryption-Key'))
        encryption_iv = bytes.fromhex(request.headers.get('Encryption-IV'))
        
        if not encryption_key or not encryption_iv:
            return jsonify({"status": "error", "message": "Encryption key or IV missing"}), 400
        
        full_encrypted_data = encryption_key + encryption_iv + encrypted_message
        decrypted_message = decrypt_message(full_encrypted_data).decode()
        
        # Process the decrypted message here
        print(f"Received and decrypted message: {decrypted_message}")
        
        return jsonify({"status": "success", "message": "Message received and decrypted"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

def run_socket_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    #context.load_cert_chain(certfile="path/to/cert.pem", keyfile="path/to/key.pem")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('localhost', 12345))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as secure_sock:
            while True:
                conn, addr = secure_sock.accept()
                with conn:
                    data = conn.recv(1024)
                    if not data:
                        break
                    decrypted_message = decrypt_message(data)
                    print(f"Received and decrypted message: {decrypted_message}")

if __name__ == '__main__':
    # To test
    app.run(ssl_context='adhoc')
    # if actual production we use wgsi server, figuring that out
    # run_socket_server()  # to run the socket server
    