from Crypto.Cipher import AES, Blowfish, ChaCha20
from Crypto.Random import get_random_bytes

def encrypt_message(plaintext, algo='AES'): #AES by default
    # Convert string to bytes if needed for encryption
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Assigning algorithm codes: a = AES, b = Blowfish, c = ChaCha20
    algoCodes = {'AES': b'a', 'Blowfish': b'b', 'ChaCha20': b'c'}
    if algo not in algoCodes:
        raise ValueError("Unsupported algorithm")
    
    # Generate key, IV and encrypt based on selected algorithm
    if algo == 'AES':
        key = get_random_bytes(32)  # 256 bits for AES-256
        iv = get_random_bytes(16)   # 128 bits IV
        cipher = AES.new(key, AES.MODE_CFB, iv)
        
    elif algo == 'Blowfish':
        key = get_random_bytes(56)  # 448 bits for max security
        iv = get_random_bytes(8)    # 64 bits IV
        cipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
        
    else:  # ChaCha20
        key = get_random_bytes(32)  # 256 bits
        iv = get_random_bytes(16)   # 128 bits nonce
        cipher = ChaCha20.new(key=key, nonce=iv)

    # Encrypt and combine everything
    ciphertext = cipher.encrypt(plaintext)
    return algoCodes[algo] + key + iv + ciphertext

def decrypt_message(encrypted_message, decode=True):
    # Get algorithm code (first byte)
    algoCode = encrypted_message[0:1]
    encrypted_message = encrypted_message[1:]
    
    # Decrypt based on algorithm code
    if algoCode == b'a':  # AES
        key = encrypted_message[:32]        
        iv = encrypted_message[32:48]       
        ciphertext = encrypted_message[48:] 
        decipher = AES.new(key, AES.MODE_CFB, iv)
        
    elif algoCode == b'b':  # Blowfish
        key = encrypted_message[:56]        
        iv = encrypted_message[56:64]       
        ciphertext = encrypted_message[64:] 
        decipher = Blowfish.new(key, Blowfish.MODE_CFB, iv)
        
    elif algoCode == b'c':  # ChaCha20
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
