from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

original_message = "Hola mundo criptográfico, ¡usando PBKDF2 para la clave!"
print(f"Mensaje original: {original_message}")

def derive_key(clave, salt):
    key = PBKDF2(clave, salt, dkLen=16, count=1000000, hmac_hash_module=SHA256)
    return key

def encryptar_mensage(mensaje, clave):
    salt = get_random_bytes(16)
    key = derive_key(clave, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(mensaje.encode('utf-8'))
    print(f"Clave derivada (hex): {key.hex()}")
    print(f"Texto cifrado (hex): {ciphertext.hex()}")
    return salt, nonce, tag, ciphertext

def desencryptar_mensage(ciphertext, clave, salt, nonce, tag):
    key = derive_key(clave, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

clave = input("Introduce la clave para derivar: ")
salt, nonce, tag, cyphertext = encryptar_mensage(original_message, clave)
decrypted_message = desencryptar_mensage(cyphertext, clave, salt, nonce, tag)
print(f"Mensaje descifrado: {decrypted_message}")