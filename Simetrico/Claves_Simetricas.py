from Crypto.Random import get_random_bytes
from os import chmod, stat
import stat as stat_module
from Crypto.Cipher import AES

KEY_FILE = 'key.bin'

def generar_guardar_clave(filename):
    key = get_random_bytes(16)

    with open(filename, 'wb') as key_file:
        key_file.write(key)

    # Cambiar permisos del archivo para que solo el propietario pueda leerlo
    chmod(filename, stat_module.S_IRUSR)
    print(f"Clave generada y guardada en {filename}.")
    return key

def cargar_clave(filename):
    with open(filename, 'rb') as key_file:
        key = key_file.read()
    return key

key = cargar_clave(KEY_FILE)
if not key:
    key = generar_guardar_clave(KEY_FILE)

print(f"Clave cargada: {key.hex()}")

# Encriptar y desencriptar un mensaje de ejemplo
message = "Este es un mensaje secreto que será cifrado y descifrado con la clave almacenada."
print(f"Mensaje original: {message}")
cipher = AES.new(key, AES.MODE_GCM)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
print(f'Mensaje cifrado (hex): {ciphertext.hex()}')

cipher2 = AES.new(key, AES.MODE_GCM, nonce=nonce)
decrypted_message = cipher2.decrypt_and_verify(ciphertext, tag)
print(f"Mensaje descifrado: {decrypted_message.decode('utf-8')}")
