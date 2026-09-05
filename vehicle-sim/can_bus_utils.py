import can
import time
import socket
import json
import threading
import os
import struct

# Standard CAN IDs for vehicle simulation
CAN_ID_ENGINE = 0x0C4        # Engine RPM, Vehicle Speed
CAN_ID_BRAKES = 0x1A0        # Brake Pressure, ABS status
CAN_ID_INFOTAINMENT = 0x2B0  # Door locks, HVAC status
CAN_ID_GATEWAY = 0x000       # Gateway Heartbeat & System Diagnostics

DEFAULT_BROKER_HOST = os.getenv("CAN_BROKER_HOST", "127.0.0.1")
DEFAULT_BROKER_PORT = int(os.getenv("CAN_BROKER_PORT", "9999"))

class VirtualCANBrokerServer:
    """A lightweight UDP/TCP broker for broadcasting CAN frames across processes/containers on Windows/Docker."""
    def __init__(self, host="0.0.0.0", port=9999):
        self.host = host
        self.port = port
        self.clients = set()
        self.running = False
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.running = True
        print(f"[CAN Broker] Listening on {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                if addr not in self.clients:
                    self.clients.add(addr)
                # Broadcast data to all registered endpoints except sender
                for client in list(self.clients):
                    if client != addr:
                        try:
                            self.sock.sendto(data, client)
                        except Exception:
                            self.clients.discard(client)
            except Exception as e:
                if not self.running:
                    break
                print(f"[CAN Broker Error] {e}")

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

def get_can_bus(channel="test", interface="virtual"):
    """
    Factory function for obtaining a CAN bus instance.
    Uses socketcan on Linux if available, or python-can virtual bus.
    """
    try:
        if os.name != "nt" and interface == "socketcan":
            return can.Bus(channel=channel, interface="socketcan")
        else:
            return can.Bus(channel=channel, interface="virtual")
    except Exception as e:
        print(f"[CAN Bus Warning] Fallback to virtual bus: {e}")
        return can.Bus(channel="test", interface="virtual")

def encode_engine_data(rpm: int, speed_kmh: int) -> bytes:
    """Encode RPM (0-8000) and Speed (0-250 km/h) into 8 CAN payload bytes."""
    rpm_bytes = struct.pack(">H", min(8000, max(0, rpm)))
    speed_byte = bytes([min(250, max(0, speed_kmh))])
    # 2 bytes RPM, 1 byte Speed, 5 bytes padding
    return rpm_bytes + speed_byte + bytes([0]*5)

def decode_engine_data(payload: bytes):
    if len(payload) < 3:
        return {"rpm": 0, "speed": 0}
    rpm = struct.unpack(">H", payload[:2])[0]
    speed = payload[2]
    return {"rpm": rpm, "speed": speed}

def encode_brake_data(pressure_psi: int, abs_active: bool) -> bytes:
    """Encode Brake Pressure (0-2000 psi) and ABS flag into 8 CAN payload bytes."""
    press_bytes = struct.pack(">H", min(2000, max(0, pressure_psi)))
    abs_byte = bytes([1 if abs_active else 0])
    return press_bytes + abs_byte + bytes([0]*5)

def decode_brake_data(payload: bytes):
    if len(payload) < 3:
        return {"pressure": 0, "abs": False}
    press = struct.unpack(">H", payload[:2])[0]
    abs_active = bool(payload[2])
    return {"pressure": press, "abs": abs_active}

def encode_infotainment_data(doors_locked: bool, hvac_temp: int) -> bytes:
    """Encode door lock status and HVAC temp into CAN frame payload."""
    lock_byte = bytes([1 if doors_locked else 0])
    temp_byte = bytes([min(35, max(15, hvac_temp))])
    return lock_byte + temp_byte + bytes([0]*6)

def decode_infotainment_data(payload: bytes):
    if len(payload) < 2:
        return {"doors_locked": True, "hvac_temp": 22}
    return {"doors_locked": bool(payload[0]), "hvac_temp": payload[1]}
