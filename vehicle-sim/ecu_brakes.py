import time
import os
import sys
import can

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from can_bus_utils import get_can_bus, CAN_ID_BRAKES, encode_brake_data

def run_brakes_ecu():
    bus = get_can_bus()
    print("[Brake ECU] Started emitting CAN telemetry...")
    
    pressure = 0
    abs_active = False
    braking = False
    cycle_counter = 0

    try:
        while True:
            cycle_counter += 1
            if cycle_counter % 100 == 0:
                braking = not braking

            if braking:
                pressure = min(1500, pressure + 50)
                abs_active = pressure > 1200
            else:
                pressure = max(0, pressure - 60)
                abs_active = False

            payload = encode_brake_data(pressure, abs_active)
            msg = can.Message(arbitration_id=CAN_ID_BRAKES, data=payload, is_extended_id=False)
            bus.send(msg)
            
            # Emit at 50ms interval (20 Hz)
            time.sleep(0.05)
    except KeyboardInterrupt:
        print("[Brake ECU] Stopped.")

if __name__ == "__main__":
    run_brakes_ecu()
