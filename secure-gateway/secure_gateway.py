import time
import threading

class SecureGatewayIsolationManager:
    """Automated zone isolation rule engine for ECU CAN bus protection."""
    def __init__(self):
        self.isolated_ids = set()
        self.isolation_log = []
        self.lock = threading.Lock()

    def evaluate_alert_and_isolate(self, alert: dict) -> dict:
        """Evaluates an incoming alert and triggers automated zone isolation if severity is HIGH or CRITICAL."""
        severity = alert.get("severity", "LOW")
        arb_id_str = alert.get("arbitration_id", "0x000")
        
        if severity in ["HIGH", "CRITICAL"]:
            with self.lock:
                if arb_id_str not in self.isolated_ids:
                    self.isolated_ids.add(arb_id_str)
                    action_record = {
                        "timestamp": time.time(),
                        "action": "ISOLATE",
                        "arbitration_id": arb_id_str,
                        "reason": f"Automated response to {alert.get('attack_type', 'Intrusion')} ({severity})",
                        "status": "ACTIVE_ISOLATION"
                    }
                    self.isolation_log.append(action_record)
                    print(f"[Secure Gateway] AUTOMATED ISOLATION ACTIVATED: Blocked {arb_id_str} on bus network.")
                    return action_record
        return None

    def is_id_blocked(self, arbitration_id_int: int) -> bool:
        arb_str = f"0x{arbitration_id_int:03X}"
        with self.lock:
            return arb_str in self.isolated_ids

    def restore_id(self, arb_id_str: str) -> dict:
        """Manual restore action for demo purposes."""
        with self.lock:
            if arb_id_str in self.isolated_ids:
                self.isolated_ids.remove(arb_id_str)
                record = {
                    "timestamp": time.time(),
                    "action": "RESTORE",
                    "arbitration_id": arb_id_str,
                    "reason": "Manual operator authorization from SOC dashboard",
                    "status": "RESTORED"
                }
                self.isolation_log.append(record)
                print(f"[Secure Gateway] ISOLATION REMOVED: Restored traffic for {arb_id_str}.")
                return record
        return {"status": "NOT_FOUND"}

    def get_status(self) -> dict:
        with self.lock:
            return {
                "active_isolated_ids": list(self.isolated_ids),
                "isolation_history": list(self.isolation_log)
            }
