import ipfshttpclient
from Crypto.Cipher import AES
import io

# IPFS client setup
api_url = "/ip4/127.0.0.1/tcp/5001"
client = ipfshttpclient.connect(api_url)

static_aes_key = b'ThisIsAStaticKey32Bytes123456789'
static_nonce = b'sameerpanhwar_nonce'

def encrypt(file_path, key, nonce):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    ciphertext_io = io.BytesIO(ciphertext)

    ipfs_hash = client.add(ciphertext_io)

    return ipfs_hash

def decrypt(ipfs_hash, file_path, key, nonce):
    response = client.cat(ipfs_hash)

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(response)

    with open(file_path, 'wb') as decrypted_file:
        decrypted_file.write(plaintext)



if __name__ == "__main__":
    file_path = "song.mp4" 

    # Encrypt and upload content to IPFS
    ipfs_hash = encrypt_and_upload_to_ipfs(file_path, static_aes_key, static_nonce)
    print(f"File uploaded to IPFS with hash: {ipfs_hash}")

    # Download and decrypt content from IPFS using cat
    download_and_decrypt_from_ipfs('QmWeh1ju3Zfnuhki3pvCXTWvdmGsfEHLHprvQzzdoDxork', file_path + "_encrypt.mp4", static_aes_key, static_nonce)
    print("File downloaded and decrypted successfully.")


# download_and_decrypt_from_ipfs('QmWeh1ju3Zfnuhki3pvCXTWvdmGsfEHLHprvQzzdoDxork', file_path + "_encrypt.mp4")
# print("File downloaded and decrypted successfully.")