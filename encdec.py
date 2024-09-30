from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

# Generates a valid 24-byte parity-adjusted 3DES key
def genKey():
    while True:
        try:
            key = DES3.adjust_key_parity(get_random_bytes(24))
            return key
        # if key is not 24 bytes long or if TDES key degenerates into Single DES
        except ValueError:
            pass

# ENCRYPTION (in CFB mode)
def encrypt_message(plaintext):
    # Ensure plaintext is a bytes object before encryption
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')  # Convert string to bytes

    key = genKey()
    iv = get_random_bytes(8) # 8-byte IV (Initialized Vector) for ensuring randomness of encryption
    cipher = DES3.new(key, DES3.MODE_CFB, iv)
    cipherText = cipher.encrypt(plaintext)
    return key + iv + cipherText

# DECRYPTION (in CFB mode)
def decrypt_message(encrypted_message):
    key = encrypted_message[:24] # first 24 bytes are the key
    iv = encrypted_message[24:32] # next 8-bits are the iv
    cipherText = encrypted_message[32:] # rest is the message
    decipher = DES3.new(key, DES3.MODE_CFB, iv)
    decryptedText = decipher.decrypt(cipherText)
    return decryptedText

# CFB MODE (Cipher Feedback) :-
# Mode of operation that turns block cipher into stream cipher.
# Each byte of plaintext is XORed with a byte taken from keystream.

# Other Modes - Electronic Code Book, Cipher-Block Chaining, CounTer Mode, EAX Mode etc