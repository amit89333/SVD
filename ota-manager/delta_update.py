import json
import time
import os
import sys

sys.path.append(os.path.dirname(__file__))
from sign_update import sign_firmware_package
from verify_update import verify_firmware_package

def create_delta_patch(old_bytes: bytes, new_bytes: bytes) -> dict:
    """Computes byte-level difference delta patch for efficient firmware update transmission."""
    # Simple byte diff patch representation
    patch_ops = []
    min_len = min(len(old_bytes), len(new_bytes))
    for i in range(min_len):
        if old_bytes[i] != new_bytes[i]:
            patch_ops.append({"offset": i, "value": new_bytes[i]})
    if len(new_bytes) > len(old_bytes):
        patch_ops.append({"append": list(new_bytes[len(old_bytes):])})
        
    delta_payload = json.dumps({"base_len": len(old_bytes), "ops": patch_ops}).encode("utf-8")
    sig = sign_firmware_package(delta_payload)
    
    return {
        "delta_payload": delta_payload,
        "signature": sig.hex(),
        "original_size": len(new_bytes),
        "delta_size": len(delta_payload)
    }

def apply_delta_patch(old_bytes: bytes, delta_record: dict) -> bytes:
    """Verifies signature and applies delta patch on ECU side."""
    delta_payload = delta_record["delta_payload"]
    sig = bytes.fromhex(delta_record["signature"])
    
    if not verify_firmware_package(delta_payload, sig):
        raise ValueError("OTA Delta Patch Verification Failed: Invalid Signature!")
        
    meta = json.loads(delta_payload.decode("utf-8"))
    res = bytearray(old_bytes)
    for op in meta["ops"]:
        if "offset" in op:
            res[op["offset"]] = op["value"]
        elif "append" in op:
            res.extend(op["append"])
            
    return bytes(res)

if __name__ == "__main__":
    v1 = b"ENGINE_FIRMWARE_V1.0_INITIAL"
    v2 = b"ENGINE_FIRMWARE_V2.0_UPDATED"
    
    patch = create_delta_patch(v1, v2)
    print(f"[Delta Patch] Size reduction: {len(v2)} bytes -> {patch['delta_size']} bytes delta")
    
    updated_v1 = apply_delta_patch(v1, patch)
    assert updated_v1 == v2
    print("[Delta Patch] Applied successfully and verified!")
