from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import base64

# AES Encryption (256-bit)
def aes_encrypt(plaintext, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)  # AES-256 key
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(salt + cipher.iv + ct_bytes).decode()

def aes_decrypt(ciphertext, password):
    data = base64.b64decode(ciphertext)
    salt = data[:16]
    iv = data[16:32]
    ct = data[32:]
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# DES Encryption (Triple DES with 16-byte key)
def des_encrypt(plaintext, password):
    salt = get_random_bytes(8)
    key = PBKDF2(password, salt, dkLen=16)  # TDES requires 16/24-byte keys
    cipher = DES3.new(key, DES3.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), DES3.block_size))
    return base64.b64encode(salt + cipher.iv + ct_bytes).decode()

def des_decrypt(ciphertext, password):
    data = base64.b64decode(ciphertext)
    salt = data[:8]
    iv = data[8:16]
    ct = data[16:]
    key = PBKDF2(password, salt, dkLen=16)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), DES3.block_size).decode()

# RSA Encryption (2048-bit)
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

def rsa_decrypt(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(base64.b64decode(ciphertext)).decode()

# Main Interface
def main():
    print("Text Encryption Tool")
    print("1. AES\n2. DES\n3. RSA\n")
    choice = input("Choose algorithm (1-3): ")

    if choice == '1':
        text = input("Enter text: ")
        password = input("Enter password: ")
        encrypted = aes_encrypt(text, password)
        print("\nEncrypted:", encrypted)
        decrypted = aes_decrypt(encrypted, password)
        print("Decrypted:", decrypted)

    elif choice == '2':
        text = input("Enter text: ")
        password = input("Enter password: ")
        encrypted = des_encrypt(text, password)
        print("\nEncrypted:", encrypted)
        decrypted = des_decrypt(encrypted, password)
        print("Decrypted:", decrypted)

    elif choice == '3':
        private, public = generate_rsa_keys()
        text = input("Enter text: ")
        encrypted = rsa_encrypt(text, public)
        print("\nEncrypted:", encrypted)
        decrypted = rsa_decrypt(encrypted, private)
        print("Decrypted:", decrypted)

    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()