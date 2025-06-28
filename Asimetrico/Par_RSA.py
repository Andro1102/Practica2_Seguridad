from Crypto.PublicKey import RSA

# Generar claves
def generar_claves_rsa(nombre_archivo_privada, nombre_archivo_publica, contrasena):
    key = RSA.generate(2048) 
    clave_privada_pem = key.export_key(passphrase=contrasena)

    # Guardar clave privada
    with open(nombre_archivo_privada, "wb") as f:
        f.write(clave_privada_pem)

    print(f"Clave privada generada y protegida con contraseña en '{nombre_archivo_privada}'")

    # Guardar la clave pública
    clave_publica_pem = key.publickey().export_key()
    with open(nombre_archivo_publica, "wb") as f:
        f.write(clave_publica_pem)
    print(f"Clave pública generada en '{nombre_archivo_publica}'")

contrasena= "miContrasenaSuperSegura123"
generar_claves_rsa("private_rsa_key.pem", "public_rsa_key.pem", contrasena)
print(f'Clave usada para guardar la clave privada {contrasena}')