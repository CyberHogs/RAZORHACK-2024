from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Function to derive a key from the decrypted text (same as used during encryption).
def derive_key(text, length=16):
    key = text.encode('utf-8')
    if len(key) < length:
        key += b' ' * (length - len(key))
    elif len(key) > length:
        key = key[:length]
    return key

# Function to decrypt the audio file using the derived key.
def decrypt_audio_file(encrypted_audio_path, decrypted_audio_path, decryption_key):
    # Read the encrypted audio file.
    with open(encrypted_audio_path, 'rb') as file:
        iv = file.read(16)  # Read the first 16 bytes as the IV.
        encrypted_audio = file.read()  # Read the rest as the encrypted audio data.
    
    # Create AES cipher for decryption.
    cipher = AES.new(decryption_key, AES.MODE_CBC, iv=iv)
    
    # Decrypt and unpad the audio data.
    decrypted_audio = unpad(cipher.decrypt(encrypted_audio), AES.block_size)
    
    # Save the decrypted audio to a new file.
    with open(decrypted_audio_path, 'wb') as file:
        file.write(decrypted_audio)
    
    print(f"Decrypted audio saved to: {decrypted_audio_path}")

# Example usage:
decrypted_text = "to start press a"  # The decrypted text that was used as the key during encryption.
encrypted_audio_file = 'HomerMessage.mp3'  # Path to the encrypted audio file.
decrypted_audio_file = "Homer_decrypted.mp3"  # Output path for the decrypted audio file.

# Derive the decryption key from the decrypted text.
decryption_key = derive_key(decrypted_text)

# Use the derived key to decrypt the audio file.
decrypt_audio_file(encrypted_audio_file, decrypted_audio_file, decryption_key)
