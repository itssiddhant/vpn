from Crypto.Cipher import AES, Blowfish, ChaCha20
from Crypto.Random import get_random_bytes

def encrypt_message(plaintext, algorithm='AES'):
    """
    Encrypts a message using the specified algorithm.
    
    Args:
        plaintext: The message to encrypt (string or bytes)
        algorithm: The encryption algorithm to use ('AES', 'Blowfish', or 'ChaCha20')
    
    Returns:
        bytes: algorithm_code + key + iv + ciphertext
    """
    # Convert string to bytes if needed for encryption
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Simple algorithm codes: a = AES, b = Blowfish, c = ChaCha20
    algo_codes = {'AES': b'a', 'Blowfish': b'b', 'ChaCha20': b'c'}
    if algorithm not in algo_codes:
        raise ValueError("Unsupported algorithm")
    
    # Generate key, IV and encrypt based on selected algorithm
    if algorithm == 'AES':
        key = get_random_bytes(32)  # 256 bits for AES-256
        iv = get_random_bytes(16)   # 128 bits IV
        cipher = AES.new(key, AES.MODE_CFB, iv)
        
    elif algorithm == 'Blowfish':
        key = get_random_bytes(56)  # 448 bits for max security
        iv = get_random_bytes(8)    # 64 bits IV
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
        
    else:  # ChaCha20
        key = get_random_bytes(32)  # 256 bits
        iv = get_random_bytes(16)   # 128 bits nonce
        cipher = ChaCha20.new(key=key, nonce=iv)

    # Encrypt and combine everything
    ciphertext = cipher.encrypt(plaintext)
    return algo_codes[algorithm] + key + iv + ciphertext

def decrypt_message(encrypted_message, decode=True):
    """
    Decrypts a message and optionally decodes it to string.
    
    Args:
        encrypted_message: The complete encrypted message bytes
        decode: If True, returns string. If False, returns bytes
    
    Returns:
        str or bytes: The decrypted message
    """
    # Get algorithm code (first byte)
    algo_code = encrypted_message[0:1]
    encrypted_message = encrypted_message[1:]
    
    # Decrypt based on algorithm code
    if algo_code == b'a':  # AES
        key = encrypted_message[:32]        
        iv = encrypted_message[32:48]       
        ciphertext = encrypted_message[48:] 
        decipher = AES.new(key, AES.MODE_CFB, iv)
        
    elif algo_code == b'b':  # Blowfish
        key = encrypted_message[:56]        
        iv = encrypted_message[56:64]       
        ciphertext = encrypted_message[64:] 
        decipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
        
    elif algo_code == b'c':  # ChaCha20
        key = encrypted_message[:32]        
        iv = encrypted_message[32:48]       
        ciphertext = encrypted_message[48:] 
        decipher = ChaCha20.new(key=key, nonce=iv)
        
    else:
        raise ValueError("Unknown encryption algorithm")
    
    # Decrypt the message
    decrypted = decipher.decrypt(ciphertext)
    
    # Return string if decode=True, otherwise return bytes
    return decrypted.decode('utf-8') if decode else decrypted

# # Example usage:
# if __name__ == "__main__":
#     message = "Hello World!"
    
#     # Encrypt using different algorithms
#     encrypted_aes = encrypt_message(message, "AES")
#     encrypted_blowfish = encrypt_message(message, "Blowfish")
#     encrypted_chacha = encrypt_message(message, "ChaCha20")
    
#     # Decrypt and automatically decode to string
#     print("AES:", decrypt_message(encrypted_aes))
#     print("Blowfish:", decrypt_message(encrypted_blowfish))
#     print("ChaCha20:", decrypt_message(encrypted_chacha))
    
#     # If you need bytes instead of string:
#     decrypted_bytes = decrypt_message(encrypted_aes, decode=False)