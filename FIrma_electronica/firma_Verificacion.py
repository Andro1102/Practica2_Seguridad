from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

message = b"Este es un mensaje secreto que sera firmado."

hash_obj = SHA256.new(message)

rsa_private_key = RSA.import_key(private_key)

signer = pkcs1_15.new(rsa_private_key)
signature = signer.sign(hash_obj)

print("---")
print("Mensaje original:", message.decode())
print("Firma (en bytes):", signature.hex())
print("---")

rsa_public_key = RSA.import_key(public_key)
hash_obj_verify = SHA256.new(message)
verifier = pkcs1_15.new(rsa_public_key)

try:
    verifier.verify(hash_obj_verify, signature)
    print("La firma es válida. El mensaje no ha sido alterado y proviene del firmante.")
except (ValueError, TypeError):
    print("La firma no es válida. El mensaje pudo haber sido alterado o no proviene del firmante.")
