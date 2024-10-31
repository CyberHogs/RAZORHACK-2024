from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Function to derive a key from the decrypted text.
def derive_key(text, length=16):
    # Convert the text to bytes and pad or truncate it to the specified length.
    key = text.encode('utf-8')
    if len(key) < length:
        # Pad the key if it's too short
        key += b' ' * (length - len(key))
    elif len(key) > length:
        # Truncate the key if it's too long
        key = key[:length]
    return key

# Function to encrypt the audio file using the derived key.
def encrypt_audio_file(audio_file_path, encrypted_audio_path, encryption_key):
    # Read the audio file content.
    with open(audio_file_path, 'rb') as file:
        audio_data = file.read()
    
    # Pad the audio data to be a multiple of 16 bytes (required for AES).
    padded_audio = pad(audio_data, AES.block_size)
    
    # Create AES cipher for encryption.
    cipher = AES.new(encryption_key, AES.MODE_CBC)  # Using CBC mode for better security
    iv = cipher.iv  # Initialization vector for CBC mode
    
    # Encrypt the padded audio data.
    encrypted_audio = cipher.encrypt(padded_audio)
    
    # Save the IV and encrypted audio to a new file.
    with open(encrypted_audio_path, 'wb') as file:
        file.write(iv)  # Prepend the IV for decryption later
        file.write(encrypted_audio)

    print(f"Encrypted audio saved to: {encrypted_audio_path}")

# Example usage:
decrypted_text = "to start press a"  # The decrypted text to use as the key.
audio_file = "HomerMessage_Encrypted.mp3"  # Path to the audio file you want to encrypt.
encrypted_audio_file = 'HomerMessage.mp3'  # Output path for the encrypted audio file.

# Derive the key from the decrypted text.
encryption_key = derive_key(decrypted_text)

# Use the derived key to encrypt the audio file.
encrypt_audio_file(audio_file, encrypted_audio_file, encryption_key)
