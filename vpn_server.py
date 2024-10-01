import socket
import logging
from datetime import datetime, timedelta
from encdec import decrypt_message

# Configuration
SERVER_IP = 'localhost'
SERVER_PORT = 12345

# Set up logging
logging.basicConfig(filename='vpn_server.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting configuration
RATE_LIMIT_WINDOW = timedelta(minutes=1)
MAX_REQUESTS = 10
REQUESTS_LOG = {}

def rate_limited(address):
    """Rate limits requests from a given IP address."""
    current_time = datetime.now()
    requests = REQUESTS_LOG.get(address, [])
    
    # Remove requests older than RATE_LIMIT_WINDOW
    requests = [timestamp for timestamp in requests if current_time - timestamp < RATE_LIMIT_WINDOW]
    REQUESTS_LOG[address] = requests
    
    if len(requests) >= MAX_REQUESTS:
        logging.warning(f"Rate limit exceeded for {address}")
        return False
    
    # Record this request
    REQUESTS_LOG[address].append(current_time)
    return True

def handle_client_connection(client_socket, client_address):
    """Handles client connection and message decryption."""
    if not rate_limited(client_address):
        client_socket.sendall(b'Rate limit exceeded.')
        client_socket.close()
        return

    try:
        encrypted_message = client_socket.recv(1024)
        if encrypted_message:
            decrypted_message = decrypt_message(encrypted_message)
            if decrypted_message:
                logging.info(f"Received decrypted message: {decrypted_message}")
                client_socket.sendall(b'Message received and decrypted.')
            else:
                client_socket.sendall(b'Failed to decrypt message.')
        else:
            logging.warning("No message received from client.")
    except Exception as e:
        logging.error(f"Error handling client connection: {e}")
    finally:
        client_socket.close()

def start_server():
    """Starts the VPN server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)
    logging.info(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        logging.info(f"Connection from {addr}")
        handle_client_connection(client_socket, addr)

if __name__ == "__main__":
    start_server()
