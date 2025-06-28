from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC 


# Claves RSA
print("Generando claves RSA...")
rsa_key = RSA.generate(2048)
rsa_private_pem = rsa_key.export_key(pkcs=8).decode('utf-8')
print(f'clave privada RSA (PEM):\n{rsa_private_pem}\n')
rsa_public_pem = rsa_key.publickey().export_key().decode('utf-8')
print(f'clave pública RSA (PEM):\n{rsa_public_pem}\n')\

# Claves EdDSA
print("Generando claves EdDSA...")
eddsa_key = ECC.generate(curve='ed25519')   
eddsa_private_pem = eddsa_key.export_key(format='PEM').encode('utf-8')
print(f'clave privada EdDSA (PEM):\n{eddsa_private_pem}\n')
eddsa_public_pem = eddsa_key.public_key().export_key(format='PEM').encode('utf-8')
print(f'clave pública EdDSA (PEM):\n{eddsa_public_pem}\n')  

