import os
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

sys.path.append(os.path.dirname(__file__))
from sign_update import get_or_generate_keypair

def verify_firmware_package(firmware_bytes: bytes, signature: bytes) -> bool:
    """Verifies firmware byte payload against Ed25519 signature."""
    _, pub_key = get_or_generate_keypair()
    try:
        pub_key.verify(signature, firmware_bytes)
        print("[OTA Verifier] Signature verification SUCCESSFUL. Package is authentic.")
        return True
    except InvalidSignature:
        print("[OTA Verifier ERROR] Signature verification FAILED! Tampering detected.")
        return False
    except Exception as e:
        print(f"[OTA Verifier Error] {e}")
        return False

if __name__ == "__main__":
    from sign_update import sign_firmware_package
    payload = b"SDV_FIRMWARE_V2.2.0_ENGINE_CONTROL"
    sig = sign_firmware_package(payload)
    
    print("Testing valid signature verification...")
    assert verify_firmware_package(payload, sig) == True

    print("Testing tampered payload verification...")
    tampered_payload = b"SDV_FIRMWARE_V2.2.0_ENGINE_CONTROL_MALICIOUS_PATCH"
    assert verify_firmware_package(tampered_payload, sig) == False
    print("All OTA verification tests passed!")
