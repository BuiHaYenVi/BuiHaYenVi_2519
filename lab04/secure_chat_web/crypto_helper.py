from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
import hashlib

# ----------------- AES Helpers -----------------

def encrypt_aes(key, plaintext):
    """Encrypt plaintext using AES-128 in CBC mode. Returns IV + Ciphertext bytes."""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_aes(key, encrypted_data):
    """Decrypt IV + Ciphertext bytes using AES-128 in CBC mode. Returns plaintext string."""
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_bytes.decode('utf-8')

# ----------------- RSA Helpers -----------------

def generate_rsa_keypair():
    """Generates a 2048-bit RSA key pair. Returns (private_key_pem, public_key_pem) bytes."""
    key = RSA.generate(2048)
    private_key_pem = key.export_key(format='PEM')
    public_key_pem = key.publickey().export_key(format='PEM')
    return private_key_pem, public_key_pem

def encrypt_rsa(public_key_pem, data):
    """Encrypt data using RSA public key."""
    pub_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(data)

def decrypt_rsa(private_key_pem, encrypted_data):
    """Decrypt data using RSA private key."""
    priv_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(encrypted_data)

# ----------------- DH Helpers -----------------

def generate_dh_parameters():
    """Generates DH parameters with generator=2, key_size=1024."""
    return dh.generate_parameters(generator=2, key_size=1024)

def serialize_dh_parameters(parameters):
    """Serializes DH parameters to PEM bytes."""
    return parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )

def deserialize_dh_parameters(pem_bytes):
    """Deserializes DH parameters from PEM bytes."""
    return serialization.load_pem_parameters(pem_bytes)

def generate_dh_keypair(parameters):
    """Generates DH private and public keys using given parameters."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_dh_public_key(public_key):
    """Serializes DH public key to PEM bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_dh_public_key(pem_bytes):
    """Deserializes DH public key from PEM bytes."""
    return serialization.load_pem_public_key(pem_bytes)

def derive_shared_secret(private_key, peer_public_key):
    """Derives shared secret bytes using private key and peer's public key."""
    return private_key.exchange(peer_public_key)

def derive_aes_key(shared_secret):
    """Hashes the DH shared secret using SHA-256 and uses the first 16 bytes for AES."""
    return hashlib.sha256(shared_secret).digest()[:16]
