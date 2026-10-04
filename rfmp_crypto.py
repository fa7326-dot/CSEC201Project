import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import os

# --- RSA KEY MANAGEMENT ---

def generate_rsa_keys():
    """Generate RSA public/private key pair and return PEM formatted strings."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return priv_pem, pub_pem

def rsa_encrypt(public_key_pem: str, plaintext: str) -> str:
    """Encrypt a string using an RSA public key and return base64 string."""
    pub_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    ciphertext = pub_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(private_key_pem: str, ciphertext_b64: str) -> str:
    """Decrypt a base64 encoded string using an RSA private key."""
    priv_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    ciphertext = base64.b64decode(ciphertext_b64.encode('utf-8'))
    decrypted = priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

# --- CAESAR CIPHER ---

def caesar_encrypt(text: str, key: str) -> str:
    """Encrypt text using Caesar cipher derived from numeric key/shift."""
    shift = sum(ord(c) for c in key) % 26
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)

def caesar_decrypt(text: str, key: str) -> str:
    """Decrypt text using Caesar cipher derived from numeric key/shift."""
    shift = sum(ord(c) for c in key) % 26
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)

# --- AES CIPHER (CBC MODE) ---

def aes_encrypt(text: str, key: str) -> str:
    """Encrypt text using AES-256 CBC with a derived 32-byte key."""
    # Ensure key is exactly 32 bytes (256 bits)
    aes_key = key.zfill(32)[:32].encode('utf-8')
    iv = os.urandom(16)
    
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    
    # Store IV along with ciphertext
    return base64.b64encode(iv + ct).decode('utf-8')

def aes_decrypt(text_b64: str, key: str) -> str:
    """Decrypt base64 text using AES-256 CBC."""
    aes_key = key.zfill(32)[:32].encode('utf-8')
    raw_data = base64.b64decode(text_b64.encode('utf-8'))
    
    iv = raw_data[:16]
    ct = raw_data[16:]
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_pt = decryptor.update(ct) + decryptor.finalize()
    
    unpadder = sym_padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded_pt) + unpadder.finalize()
    return pt.decode('utf-8')

# --- PAYLOAD ENCRYPTION ROUTER ---

def encrypt_payload(algorithm: str, text: str, session_key: str) -> str:
    if algorithm.upper() == "AES":
        return aes_encrypt(text, session_key)
    elif algorithm.upper() == "CAESAR":
        return caesar_encrypt(text, session_key)
    return text

def decrypt_payload(algorithm: str, text: str, session_key: str) -> str:
    if algorithm.upper() == "AES":
        return aes_decrypt(text, session_key)
    elif algorithm.upper() == "CAESAR":
        return caesar_decrypt(text, session_key)
    return text