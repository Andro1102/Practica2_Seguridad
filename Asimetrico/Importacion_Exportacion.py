from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

mensaje_a_cifrar = "Este es un mensaje de prueba para la importación."
#exportar la clave pública
with open('public_rsa_key.pem', 'rb') as f:
    clave_public = f.read()

import_public = RSA.import_key(clave_public)
cipher_rsa_public = PKCS1_OAEP.new(import_public)
#cifrar el mensaje
mensaje_bytes = mensaje_a_cifrar.encode("utf-8")
mensaje_cifrado = cipher_rsa_public.encrypt(mensaje_bytes)
print('mensaje cifrado con la clave pública (hex)', mensaje_cifrado.hex())