import time
import os
import sys
import can

# Ensure module path imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from can_bus_utils import get_can_bus, CAN_ID_ENGINE, encode_engine_data

def run_engine_ecu():
    bus = get_can_bus()
    print("[Engine ECU] Started emitting CAN telemetry...")
    
    rpm = 800
    speed = 0
    accelerating = True

    try:
        while True:
            # Simulate basic drive cycle
            if accelerating:
                rpm += 50
                speed += 1
                if rpm >= 3500:
                    accelerating = False
            else:
                rpm -= 40
                speed -= 1
                if rpm <= 1000:
                    accelerating = True

            payload = encode_engine_data(rpm, speed)
            msg = can.Message(arbitration_id=CAN_ID_ENGINE, data=payload, is_extended_id=False)
            bus.send(msg)
            
            # Emit at ~20ms interval (50 Hz) matching standard car CAN frequency
            time.sleep(0.02)
    except KeyboardInterrupt:
        print("[Engine ECU] Stopped.")

if __name__ == "__main__":
    run_engine_ecu()
