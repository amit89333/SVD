import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "ota_ed25519.priv")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "ota_ed25519.pub")

def get_or_generate_keypair():
    """Retrieves or generates Ed25519 keypair for OTA firmware signing."""
    if not os.path.exists(PRIVATE_KEY_PATH):
        priv_key = ed25519.Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        return priv_key, pub_key

    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBLIC_KEY_PATH, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    return priv_key, pub_key

def sign_firmware_package(firmware_bytes: bytes) -> bytes:
    """Signs firmware byte array using Ed25519 private key."""
    priv_key, _ = get_or_generate_keypair()
    signature = priv_key.sign(firmware_bytes)
    return signature

if __name__ == "__main__":
    test_data = b"SDV_FIRMWARE_V2.2.0_ENGINE_CONTROL"
    sig = sign_firmware_package(test_data)
    print(f"[OTA Signer] Generated Ed25519 signature: {sig.hex()[:32]}...")
