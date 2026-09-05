import time
import os
import sys
import can

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from can_bus_utils import get_can_bus, CAN_ID_GATEWAY

def run_gateway_ecu():
    bus = get_can_bus()
    print("[Gateway ECU] Started emitting heartbeats and gateway telemetry...")
    
    seq = 0
    try:
        while True:
            seq = (seq + 1) % 256
            # 8-byte heartbeat payload with sequence counter and status code 0x01 (Healthy)
            payload = bytes([seq, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            msg = can.Message(arbitration_id=CAN_ID_GATEWAY, data=payload, is_extended_id=False)
            bus.send(msg)
            
            # Emit heartbeat every 100ms
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("[Gateway ECU] Stopped.")

if __name__ == "__main__":
    run_gateway_ecu()
