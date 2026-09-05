import hashlib
import json
import time
import os
import threading

LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), "audit_chain.jsonl")

class HashChainAuditLogger:
    """Cryptographic append-only audit log where each entry hashes the previous entry."""
    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, log_path=LOG_FILE_PATH):
        self.log_path = log_path
        self.lock = threading.Lock()
        self.last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        if not os.path.exists(self.log_path):
            return self.GENESIS_HASH
        last_h = self.GENESIS_HASH
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        record = json.loads(line)
                        last_h = record.get("hash", last_h)
                    except Exception:
                        pass
        return last_h

    def log_event(self, event_type: str, details: dict) -> dict:
        """Appends a new event entry to the hash chain."""
        with self.lock:
            ts = time.time()
            prev_hash = self.last_hash
            
            entry_body = {
                "timestamp": ts,
                "event_type": event_type,
                "details": details,
                "prev_hash": prev_hash
            }
            
            serialized = json.dumps(entry_body, sort_keys=True)
            entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            
            full_record = {
                **entry_body,
                "hash": entry_hash
            }
            
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(full_record) + "\n")
                
            self.last_hash = entry_hash
            return full_record

    def verify_chain_integrity(self) -> tuple[bool, list[str]]:
        """Walks the complete audit chain and verifies that every hash signature matches."""
        if not os.path.exists(self.log_path):
            return True, ["Audit log empty. Chain intact."]

        errors = []
        expected_prev = self.GENESIS_HASH
        index = 0

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                index += 1
                if not line.strip():
                    continue
                record = json.loads(line)
                curr_hash = record.get("hash")
                prev_h = record.get("prev_hash")
                
                if prev_h != expected_prev:
                    errors.append(f"Broken prev_hash link at entry #{index}! Expected {expected_prev[:10]}..., got {prev_h[:10]}...")

                entry_body = {
                    "timestamp": record["timestamp"],
                    "event_type": record["event_type"],
                    "details": record["details"],
                    "prev_hash": record["prev_hash"]
                }
                recomputed_hash = hashlib.sha256(json.dumps(entry_body, sort_keys=True).encode("utf-8")).hexdigest()
                
                if recomputed_hash != curr_hash:
                    errors.append(f"TAMPER DETECTED at entry #{index}! Stored hash {curr_hash[:10]}... != Computed hash {recomputed_hash[:10]}...")
                
                expected_prev = curr_hash

        is_valid = len(errors) == 0
        return is_valid, errors

if __name__ == "__main__":
    logger = HashChainAuditLogger()
    r1 = logger.log_event("SYSTEM_BOOT", {"status": "OK", "ecus": 4})
    r2 = logger.log_event("ATTACK_DETECTED", {"type": "Spoofing", "id": "0x1A0"})
    
    valid, errs = logger.verify_chain_integrity()
    print(f"Chain Integrity Status: {'VALID' if valid else 'TAMPERED'}")
    for msg in errs:
        print("  -", msg)
