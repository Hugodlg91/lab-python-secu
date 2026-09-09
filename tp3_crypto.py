import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def encrypt_message(message: str, key: bytes):
    # Génération d'un IV (Vecteur d'Initialisation) aléatoire de 16 octets
    iv = os.urandom(16)
    
    # Remplissage (padding) pour aligner les données sur des blocs de 128 bits
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    # Chiffrement AES-256 en mode CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv + ciphertext

def decrypt_message(encrypted_data: bytes, key: bytes):
    # Extraction de l'IV (les 16 premiers octets)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Déchiffrement AES-256 CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Retrait du padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode()

if __name__ == "__main__":
    # Clé AES-256 de 32 octets (256 bits)
    key = os.urandom(32)
    original_message = "Message confidentiel du lab Python Sécu"
    
    print(f"Message d'origine : {original_message}")
    
    # Chiffrement
    encrypted = encrypt_message(original_message, key)
    print(f"Chiffré (hex)     : {encrypted.hex()}")
    
    # Déchiffrement
    decrypted = decrypt_message(encrypted, key)
    print(f"Déchiffré         : {decrypted}")