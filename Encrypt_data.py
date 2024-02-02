
from Crypto.Cipher import AES
import io
import hashlib
from Crypto.Protocol.KDF import PBKDF2

# key = b'ThisIsAStaticKey32Bytes123456789'
nonce = b'sameerpanhwar_nonce'

def generate_key(email):
    
    key_size = 16  
    hashed_key = hashlib.sha256(email.encode('utf-8')).digest()[:key_size]

    return hashed_key

def encrypt(file_content,email):
    key = generate_key(email)
    plaintext = file_content
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    ciphertext_io = io.BytesIO(ciphertext)
    return ciphertext_io

def decrypt(response,email):
    key = generate_key(email)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(response)
    return plaintext
