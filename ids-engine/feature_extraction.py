import math
import numpy as np
from collections import defaultdict, deque

def calculate_entropy(data: bytes) -> float:
    """Computes Shannon entropy of payload byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = defaultdict(int)
    for b in data:
        counts[b] += 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)

def calculate_hamming_distance(data1: bytes, data2: bytes) -> int:
    """Calculates bitwise Hamming distance between two payloads."""
    if not data1 or not data2:
        return 0
    min_len = min(len(data1), len(data2))
    distance = 0
    for b1, b2 in zip(data1[:min_len], data2[:min_len]):
        distance += bin(b1 ^ b2).count('1')
    distance += abs(len(data1) - len(data2)) * 8
    return distance

class CANFeatureExtractor:
    """Sliding-window feature extraction engine for streaming CAN traffic."""
    def __init__(self, window_size=20):
        self.window_size = window_size
        self.last_timestamps = {}
        self.last_payloads = {}
        self.id_counts = defaultdict(int)
        self.total_frames = 0
        self.time_window = deque(maxlen=window_size)

    def process_frame(self, arbitration_id: int, payload: bytes, timestamp: float) -> dict:
        self.total_frames += 1
        self.id_counts[arbitration_id] += 1
        self.time_window.append(timestamp)

        # 1. Inter-arrival time (iat)
        last_t = self.last_timestamps.get(arbitration_id, timestamp)
        iat = max(0.0, timestamp - last_t)
        self.last_timestamps[arbitration_id] = timestamp

        # 2. Burst rate (frames per second in current sliding window)
        if len(self.time_window) > 1:
            window_duration = max(0.0001, self.time_window[-1] - self.time_window[0])
            fps = len(self.time_window) / window_duration
        else:
            fps = 1.0

        # 3. Payload Entropy
        entropy = calculate_entropy(payload)

        # 4. Hamming distance from previous frame of same arbitration ID
        last_p = self.last_payloads.get(arbitration_id, payload)
        hamming_dist = calculate_hamming_distance(payload, last_p)
        self.last_payloads[arbitration_id] = payload

        # 5. ID Frequency ratio
        id_freq = self.id_counts[arbitration_id] / self.total_frames

        features = {
            "arbitration_id": float(arbitration_id),
            "iat": float(iat),
            "fps": float(fps),
            "entropy": float(entropy),
            "hamming_dist": float(hamming_dist),
            "id_freq": float(id_freq),
            "dlc": float(len(payload))
        }
        return features
