
from Crypto.Cipher import AES
import io

key = b'ThisIsAStaticKey32Bytes123456789'
nonce = b'sameerpanhwar_nonce'

def encrypt(file_content):

    plaintext = file_content
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    ciphertext_io = io.BytesIO(ciphertext)
    return ciphertext_io

def decrypt(response):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(response)
    return plaintext
