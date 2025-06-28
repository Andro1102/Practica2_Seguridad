from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

message = b"Este es un mensaje secreto que sera firmado."
hash_obj = SHA256.new(message)
rsa_private_key = RSA.import_key(private_key)

# Firmar el mensaje original
signer = pkcs1_15.new(rsa_private_key)
signature = signer.sign(hash_obj)

print("---")
print("Mensaje original:", message.decode())
print("Firma (en bytes):", signature.hex())
print("---")

rsa_public_key = RSA.import_key(public_key)
hash_obj_verify = SHA256.new(message)
verifier = pkcs1_15.new(rsa_public_key)

# Modificar intencionalmente el mensaje original
altered_message = b"Este es un mensaje secreto que sera firmadX." 
altered_hash_obj = SHA256.new(altered_message)
print(f"Mensaje modificado: {altered_message.decode()}")
try:
    verifier.verify(altered_hash_obj, signature)
    print("La firma es válida. (ERROR: Esto no debería pasar con un mensaje alterado)")
except (ValueError, TypeError):
    print("La firma NO es válida. Esto demuestra que el mensaje fue alterado después de la firma.")