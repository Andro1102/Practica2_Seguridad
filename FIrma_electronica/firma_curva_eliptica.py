from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import SHA512, SHA256 

print("--- FIRMA Y VERIFICACIÓN CON EdDSA (Ed25519) ---")

# Generar un par de claves EdDSA para la curva Ed25519
key_eddsa = ECC.generate(curve='Ed25519')
private_key_eddsa = key_eddsa.export_key(format='PEM')
public_key_eddsa = key_eddsa.public_key().export_key(format='PEM')
message_eddsa = b"Este es un mensaje para ser firmado con EdDSA."

hash_obj_eddsa = SHA512.new(message_eddsa)
eddsa_private_key = ECC.import_key(private_key_eddsa)

# Firmar el mensaje
signer_eddsa = eddsa.new(eddsa_private_key, 'rfc8032')
signature_eddsa = signer_eddsa.sign(hash_obj_eddsa)

print("Mensaje original (EdDSA):", message_eddsa.decode())
print("Firma EdDSA (en bytes):", signature_eddsa.hex())
print(f"Tamaño de la firma EdDSA: {len(signature_eddsa)} bytes") 
print("---")

# Cargar la clave pública para verificar
eddsa_public_key = ECC.import_key(public_key_eddsa)
hash_obj_verify_eddsa = SHA512.new(message_eddsa)
verifier_eddsa = eddsa.new(eddsa_public_key, 'rfc8032')

try:
    verifier_eddsa.verify(hash_obj_verify_eddsa, signature_eddsa)
    print("Verificación EdDSA: La firma es válida. El mensaje no ha sido alterado y proviene del firmante.")
except (ValueError, TypeError):
    print("Verificación EdDSA: La firma NO es válida. El mensaje pudo haber sido alterado o no proviene del firmante.")

print("---")

# --- Comparación con RSA (solo para mostrar el tamaño de la firma) ---

print("--- COMPARACIÓN CON RSA (Tamaño de Firma para 2048 bits) ---")
from Crypto.PublicKey import RSA

key_rsa = RSA.generate(2048)
dummy_signature_rsa_size = key_rsa.size_in_bytes()

print(f"Tamaño de la firma RSA (con clave de 2048 bits): {dummy_signature_rsa_size} bytes")
print("---")

print(f"Firma EdDSA (Ed25519): {len(signature_eddsa)} bytes")
print(f"Firma RSA (clave de 2048 bits): {dummy_signature_rsa_size} bytes")