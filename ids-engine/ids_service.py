import os
import sys
import time
import pickle
import numpy as np
import can

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "vehicle-sim"))
from can_bus_utils import get_can_bus
from feature_extraction import CANFeatureExtractor

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODELS_DIR, "rf_ids_model.pkl")

class IDSEngineService:
    def __init__(self):
        self.extractor = CANFeatureExtractor()
        self.model = self._load_model()
        self.feature_names = ["arbitration_id", "iat", "fps", "entropy", "hamming_dist", "id_freq", "dlc"]

    def _load_model(self):
        if not os.path.exists(MODEL_PATH):
            print("[IDS Service] Model not found. Training new model...")
            sys.path.append(os.path.dirname(__file__))
            from train_ids_model import train_and_save_model
            return train_and_save_model()
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)

    def generate_shap_explanation(self, feature_dict: dict, pred_prob: float) -> str:
        """Generates a human-readable SHAP-style explanation of why an alert was triggered."""
        arb_id = int(feature_dict["arbitration_id"])
        iat = feature_dict["iat"]
        fps = feature_dict["fps"]
        entropy = feature_dict["entropy"]
        hamming = feature_dict["hamming_dist"]
        id_freq = feature_dict["id_freq"]

        reasons = []
        if fps > 200:
            reasons.append(f"Abnormal burst rate ({fps:.1f} frames/sec vs norm ~20)")
        if iat < 0.002:
            reasons.append(f"Sub-millisecond inter-arrival time ({iat*1000:.2f}ms)")
        if entropy > 2.7:
            reasons.append(f"High payload entropy ({entropy:.2f} bits/byte)")
        if hamming > 10:
            reasons.append(f"Extreme Hamming distance mutation ({int(hamming)} bits)")
        if id_freq > 0.6:
            reasons.append(f"Dominant ID bus takeover ({id_freq*100:.1f}% total traffic)")

        if not reasons:
            reasons.append(f"Statistical deviation in arbitration ID 0x{arb_id:03X} pattern")

        return f"Confidence {pred_prob*100:.1f}% | Driven by: " + "; ".join(reasons)

    def process_msg(self, msg: can.Message):
        if msg is None or msg.is_extended_id:
            return None
            
        t_recv = time.time()
        feat = self.extractor.process_frame(msg.arbitration_id, msg.data, msg.timestamp or t_recv)
        X_feat = np.array([[feat[k] for k in self.feature_names]])
        
        prob = float(self.model.predict_proba(X_feat)[0][1])
        
        if prob > 0.65:
            # Attack detected
            latency_ms = (time.time() - t_recv) * 1000
            explanation = self.generate_shap_explanation(feat, prob)
            
            # Determine attack type signature
            arb_id = int(feat["arbitration_id"])
            if arb_id == 0x000 or feat["fps"] > 300:
                attack_type = "DoS Attack"
                severity = "CRITICAL"
            elif feat["entropy"] > 2.5:
                attack_type = "Fuzzing Attack"
                severity = "HIGH"
            elif arb_id == 0x1A0:
                attack_type = "Spoofing Attack (Brakes)"
                severity = "CRITICAL"
            else:
                attack_type = "Replay / Anomaly"
                severity = "HIGH"

            alert = {
                "timestamp": time.time(),
                "vehicle_id": "vehicle-1",
                "attack_type": attack_type,
                "severity": severity,
                "arbitration_id": f"0x{arb_id:03X}",
                "confidence": round(prob, 4),
                "latency_ms": round(latency_ms, 2),
                "explanation": explanation
            }
            return alert
        return None

def start_ids_stream_listener(callback=None):
    ids = IDSEngineService()
    bus = get_can_bus()
    print("[IDS Service] Listening live on CAN bus for security intrusions...")
    
    try:
        while True:
            msg = bus.recv(timeout=0.1)
            if msg:
                alert = ids.process_msg(msg)
                if alert:
                    print(f"[ALERT-{alert['severity']}] {alert['attack_type']} on {alert['arbitration_id']}: {alert['explanation']}")
                    if callback:
                        callback(alert)
    except KeyboardInterrupt:
        print("[IDS Service] Stopped.")

if __name__ == "__main__":
    start_ids_stream_listener()
