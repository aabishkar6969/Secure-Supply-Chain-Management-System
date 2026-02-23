# core/crypto.py
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs12

def sign_data(data: bytes, private_key):
    """Sign data using RSA private key with PSS padding."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(data: bytes, signature: bytes, public_key):
    """Verify signature using RSA public key."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def hybrid_encrypt(plaintext: bytes, recipient_public_key):
    """Hybrid encryption: AES-256-GCM + RSA-OAEP."""
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    auth_tag = encryptor.tag
    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {
        'encrypted_key': encrypted_key,
        'iv': iv,
        'auth_tag': auth_tag,
        'ciphertext': ciphertext
    }

def hybrid_decrypt(encrypted_package, private_key):
    """Decrypt hybrid-encrypted data."""
    aes_key = private_key.decrypt(
        encrypted_package['encrypted_key'],
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(encrypted_package['iv'], encrypted_package['auth_tag'])
    ).decryptor()
    return decryptor.update(encrypted_package['ciphertext']) + decryptor.finalize()

def save_pkcs12(private_key, cert, password: bytes, filename: str):
    """Save private key + certificate as password-protected PKCS#12 file."""
    p12 = serialization.pkcs12.serialize_key_and_certificates(
        name=b"Secure Supply Chain Identity",
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    with open(filename, "wb") as f:
        f.write(p12)

def load_pkcs12(filename: str, password: bytes):
    """Load private key and certificate from PKCS#12 file."""
    with open(filename, "rb") as f:
        p12_data = f.read()
    private_key, cert, _ = serialization.pkcs12.load_key_and_certificates(p12_data, password)
    return private_key, cert