from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

message = b"Este es un mensaje de prueba que sera firmado con SHA-512."

hash_obj = SHA512.new(message)
rsa_private_key = RSA.import_key(private_key)

# Firmar el mensaje
signer = pkcs1_15.new(rsa_private_key)
signature = signer.sign(hash_obj)

print("---")
print("Mensaje original:", message.decode())
print("Firma (en bytes):", signature.hex())
print(f"Tamaño de la firma: {len(signature)} bytes") 
print("---")

rsa_public_key = RSA.import_key(public_key)
hash_obj_verify = SHA512.new(message)
verifier = pkcs1_15.new(rsa_public_key)

try:
    verifier.verify(hash_obj_verify, signature)
    print("La firma es válida. El mensaje no ha sido alterado y proviene del firmante.")
except (ValueError, TypeError):
    print("La firma no es válida. El mensaje pudo haber sido alterado o no proviene del firmante.")

print("---")
