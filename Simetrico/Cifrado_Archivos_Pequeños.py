from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
#configuración de archivos
input_file = 'texto.txt'
with open(input_file, 'rb') as infile:
    plaintext_data = infile.read()
print('texto a cifrar: ', plaintext_data)

#cifrado
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_GCM)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(plaintext_data)
print(f"Clave (hex): {key.hex()}")
print(f"Nonce (hex): {nonce.hex()}")
print(f"Texto cifrado (hex): {ciphertext.hex()}")
print(f"Tag de autenticación (hex): {tag.hex()}")

#guardar el archivo cifrado dentro de texto_cifrado.txt
with open('texto_cifrado.txt', 'wb') as outfile:
    outfile.write(nonce)
    outfile.write(tag)
    outfile.write(ciphertext)

# Descifrado
with open ('texto_cifrado.txt', 'rb') as infile:
    read_nonce = infile.read(16)  
    read_tag = infile.read(16)   
    read_ciphertext = infile.read()

cipher2 = AES.new(key, AES.MODE_GCM, nonce=read_nonce)    
deciphertext = cipher2.decrypt_and_verify(read_ciphertext, read_tag)
print(f"Texto descifrado: {deciphertext.hex()}")
# Guardar el cifrado
with open('texto_descifrado.txt', 'wb') as outfile:
    outfile.write(deciphertext)