import time
import os
import sys
import can

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from can_bus_utils import get_can_bus, CAN_ID_INFOTAINMENT, encode_infotainment_data

def run_infotainment_ecu():
    bus = get_can_bus()
    print("[Infotainment ECU] Started emitting CAN telemetry...")
    
    doors_locked = True
    hvac_temp = 22
    counter = 0

    try:
        while True:
            counter += 1
            if counter % 200 == 0:
                doors_locked = not doors_locked
            if counter % 150 == 0:
                hvac_temp = 20 if hvac_temp == 22 else 22

            payload = encode_infotainment_data(doors_locked, hvac_temp)
            msg = can.Message(arbitration_id=CAN_ID_INFOTAINMENT, data=payload, is_extended_id=False)
            bus.send(msg)
            
            # Emit at 100ms interval (10 Hz)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("[Infotainment ECU] Stopped.")

if __name__ == "__main__":
    run_infotainment_ecu()
