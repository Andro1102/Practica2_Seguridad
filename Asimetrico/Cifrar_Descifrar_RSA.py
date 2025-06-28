from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

contrasena = "miContrasenaSuperSegura123"
mensaje = "Hola mundo RSA, este es un mensaje secreto!"
print(f'mensaje sin cifrar {mensaje}')

with open ('public_rsa_key.pem', 'rb') as f:
    read_clave_publica = f.read()
clave_publica = RSA.import_key(read_clave_publica)
cipher_rsa_public = PKCS1_OAEP.new(clave_publica)

#cifrar el mensaje
mensaje_bytes = mensaje.encode("utf-8")
mensaje_cifrado = cipher_rsa_public.encrypt(mensaje_bytes)
print('mensaje cifrado con la clave pública(hex)', mensaje_cifrado.hex())

#descifrar el mensaje
with open ('private_rsa_key.pem', 'rb') as f:
    read_clave_privada = f.read()
clave_privada = RSA.import_key(read_clave_privada, passphrase=contrasena)
cipher_rsa_private = PKCS1_OAEP.new(clave_privada)
mensaje_descifrado = cipher_rsa_private.decrypt(mensaje_cifrado)
print('mensaje descifrado con la clave privada', mensaje_descifrado.decode("utf-8"))