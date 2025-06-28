from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_aes(plaintext):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return key, nonce, ciphertext, tag

def decrypt_aes(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try: 
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except ValueError:
        print ("Decryption failed. The key or data may be incorrect.")
        return None

message = 'hola mundo'
print(f'Mensaje original: {message}')
key, nonce, ciphertext, tag = encrypt_aes(message)
print(f"Clave (hex): {key.hex()}")
print(f"Nonce (hex): {nonce.hex()}")
print(f"Texto cifrado (hex): {ciphertext.hex()}")
print(f"Tag de autenticación (hex): {tag.hex()}")

# Descifrar el mensaje
decrypted_message = decrypt_aes(key, nonce, ciphertext, tag)

if decrypted_message:
    print(f"Mensaje descifrado: {decrypted_message}")
    if message == decrypted_message:
        print("Mensajes coinciden")
    else:
        print("Mensajes no coincuden")