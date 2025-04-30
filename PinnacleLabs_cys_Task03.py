from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import io
import os
from pathlib import Path
import sys

def get_downloads_path():
    """Get system's Downloads directory path"""
    return Path.home() / "Downloads"

def encrypt_image(input_path, password):
    """Encrypt image and save to Downloads folder"""
    try:
        # Verify input file exists
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")

        # Load image data
        with Image.open(input_path) as img:
            format = img.format
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format=format)
            image_data = img_byte_arr.getvalue()

        # Generate encryption parameters
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32)  # AES-256
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(image_data, AES.block_size))

        # Create output path
        downloads_dir = get_downloads_path()
        output_name = f"encrypted_{os.path.basename(input_path)}"
        output_path = downloads_dir / output_name

        # Save encrypted file
        with open(output_path, 'wb') as f:
            f.write(salt + cipher.iv + ct_bytes)

        return output_path

    except Exception as e:
        raise RuntimeError(f"Encryption failed: {str(e)}")

def decrypt_image(input_path, password):
    """Decrypt image and save to Downloads folder"""
    try:
        # Verify encrypted file exists
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Encrypted file not found: {input_path}")

        # Read encrypted data
        with open(input_path, 'rb') as f:
            data = f.read()

        # Extract components
        salt = data[:16]
        iv = data[16:32]
        ct = data[32:]

        # Derive key and decrypt
        key = PBKDF2(password, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(ct), AES.block_size)

        # Create output path
        downloads_dir = get_downloads_path()
        output_name = f"decrypted_{os.path.basename(input_path)}"
        output_path = downloads_dir / output_name

        # Save decrypted image
        with Image.open(io.BytesIO(decrypted_data)) as img:
            img.save(output_path)

        return output_path

    except Exception as e:
        raise RuntimeError(f"Decryption failed: {str(e)}")

def main():
    print("\n🔒 Image Encryption Tool 🔓")
    print("---------------------------")
    
    try:
        mode = input("Choose mode [encrypt/decrypt]: ").lower()
        path = input("Enter file path: ").strip('"').strip()
        password = input("Enter password: ")

        if mode == 'encrypt':
            output = encrypt_image(path, password)
            print(f"\n✅ Encryption successful!\n📁 File saved to: {output}")
        elif mode == 'decrypt':
            output = decrypt_image(path, password)
            print(f"\n✅ Decryption successful!\n📁 File saved to: {output}")
        else:
            print("\n❌ Invalid mode! Please choose 'encrypt' or 'decrypt'")

    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()