from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    nonce = AESGCM.generate_key(bit_length=96)
    aesgcm = AESGCM(key)
    
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    return nonce + ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    nonce = ciphertext[:12]
    aesgcm = AESGCM(key)
    
    plaintext = aesgcm.decrypt(nonce, ciphertext[12:], None)
    
    return plaintext