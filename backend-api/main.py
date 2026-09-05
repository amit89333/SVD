import os
import sys
import time
import json
import asyncio
import threading
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

# Add paths to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, "vehicle-sim"))
sys.path.append(os.path.join(BASE_DIR, "ids-engine"))
sys.path.append(os.path.join(BASE_DIR, "sbom-threat-intel"))
sys.path.append(os.path.join(BASE_DIR, "secure-gateway"))
sys.path.append(os.path.join(BASE_DIR, "ota-manager"))
sys.path.append(os.path.join(BASE_DIR, "audit-log"))
sys.path.append(os.path.join(BASE_DIR, "compliance"))
sys.path.append(os.path.join(BASE_DIR, "attack-injector"))

from can_bus_utils import get_can_bus, decode_engine_data, decode_brake_data, decode_infotainment_data, CAN_ID_ENGINE, CAN_ID_BRAKES, CAN_ID_INFOTAINMENT, CAN_ID_GATEWAY
from ids_service import IDSEngineService
from cve_correlator import scan_vehicle_sbom
from secure_gateway import SecureGatewayIsolationManager
from hash_chain_logger import HashChainAuditLogger
from sign_update import sign_firmware_package
from verify_update import verify_firmware_package
from delta_update import create_delta_patch

app = FastAPI(title="SDV Cybersecurity Management Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared platform instances
ids_engine = IDSEngineService()
gateway_mgr = SecureGatewayIsolationManager()
audit_logger = HashChainAuditLogger()

active_alerts = []
recent_telemetry = []
active_websockets: List[WebSocket] = []

class AttackRequest(BaseModel):
    attack: str
    duration: float = 5.0
    target: str = "vehicle-1"

class OTARequest(BaseModel):
    firmware_version: str = "v2.2.0"
    target_ecu: str = "Engine control unit"
    tampered: bool = False

class RestoreRequest(BaseModel):
    arbitration_id: str

# WebSockets broadcast helper
async def broadcast_ws(message: dict):
    for ws in list(active_websockets):
        try:
            await ws.send_json(message)
        except Exception:
            active_websockets.remove(ws)

# Background listener for CAN bus traffic & IDS stream
def background_can_bus_listener():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    bus = get_can_bus()
    print("[Backend API] CAN bus background ingestion & IDS monitor active.")
    
    while True:
        try:
            msg = bus.recv(timeout=0.1)
            if msg and not msg.is_extended_id:
                # Check if arbitration ID is isolated by gateway
                if gateway_mgr.is_id_blocked(msg.arbitration_id):
                    continue

                # Run IDS engine
                alert = ids_engine.process_msg(msg)
                if alert:
                    active_alerts.insert(0, alert)
                    if len(active_alerts) > 50:
                        active_alerts.pop()
                    
                    # Log alert in hash-chained audit ledger
                    audit_record = audit_logger.log_event("INTRUSION_ALERT", alert)
                    
                    # Automated zone isolation
                    iso_event = gateway_mgr.evaluate_alert_and_isolate(alert)
                    if iso_event:
                        audit_logger.log_event("ZONE_ISOLATION", iso_event)
                        asyncio.run(broadcast_ws({"type": "ISOLATION", "data": iso_event}))

                    asyncio.run(broadcast_ws({"type": "ALERT", "data": alert, "audit_hash": audit_record["hash"][:12]}))

                # Telemetry record for UI charts
                telemetry_item = {
                    "timestamp": time.time(),
                    "arbitration_id": f"0x{msg.arbitration_id:03X}",
                    "data": msg.data.hex()
                }
                if msg.arbitration_id == CAN_ID_ENGINE:
                    telemetry_item["decoded"] = decode_engine_data(msg.data)
                elif msg.arbitration_id == CAN_ID_BRAKES:
                    telemetry_item["decoded"] = decode_brake_data(msg.data)
                elif msg.arbitration_id == CAN_ID_INFOTAINMENT:
                    telemetry_item["decoded"] = decode_infotainment_data(msg.data)

                recent_telemetry.insert(0, telemetry_item)
                if len(recent_telemetry) > 30:
                    recent_telemetry.pop()

                asyncio.run(broadcast_ws({"type": "TELEMETRY", "data": telemetry_item}))
        except Exception as e:
            time.sleep(0.1)

@app.on_event("startup")
def startup_event():
    audit_logger.log_event("PLATFORM_STARTUP", {"status": "SOC_SERVICES_ONLINE"})
    t = threading.Thread(target=background_can_bus_listener, daemon=True)
    t.start()

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(ws: WebSocket):
    await ws.accept()
    active_websockets.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        active_websockets.remove(ws)

@app.get("/")
def get_dashboard_page():
    dashboard_path = os.path.join(BASE_DIR, "dashboard", "index.html")
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path)
    return HTMLResponse("<h1>SOC Dashboard loading...</h1>")

@app.get("/api/fleet")
def get_fleet_status():
    isolated = gateway_mgr.get_status()["active_isolated_ids"]
    critical_alerts = [a for a in active_alerts[:10] if a["severity"] == "CRITICAL"]
    
    if isolated or critical_alerts:
        health = "RED (Compromised / Active Isolation)"
    elif active_alerts:
        health = "AMBER (Minor Alerts Detected)"
    else:
        health = "GREEN (All Systems Operational)"

    return {
        "vehicles": [
            {
                "vehicle_id": "vehicle-1",
                "model": "SDV CyberX 2026",
                "status": health,
                "isolated_zones": isolated,
                "alert_count": len(active_alerts)
            }
        ]
    }

@app.get("/api/alerts")
def get_alerts():
    return {"alerts": active_alerts[:30]}

@app.get("/api/sbom")
def get_sbom_report():
    return scan_vehicle_sbom()

@app.get("/api/gateway/status")
def get_gateway_status():
    return gateway_mgr.get_status()

@app.post("/api/gateway/restore")
def restore_arbitration_id(req: RestoreRequest):
    record = gateway_mgr.restore_id(req.arbitration_id)
    if record.get("status") != "NOT_FOUND":
        audit_logger.log_event("ZONE_RESTORED", record)
    return record

@app.post("/api/attack/inject")
def inject_attack_endpoint(req: AttackRequest):
    audit_logger.log_event("ATTACK_INJECTED", {"attack": req.attack, "target": req.target, "duration": req.duration})
    
    def run_inj():
        if req.attack == "dos":
            from attack_dos import run_dos_attack
            run_dos_attack(duration=req.duration)
        elif req.attack == "fuzzing":
            from attack_fuzzing import run_fuzzing_attack
            run_fuzzing_attack(duration=req.duration)
        elif req.attack == "spoofing":
            from attack_spoofing import run_spoofing_attack
            run_spoofing_attack(duration=req.duration)
        elif req.attack == "replay":
            from attack_replay import run_replay_attack
            run_replay_attack(duration=req.duration)

    threading.Thread(target=run_inj, daemon=True).start()
    return {"status": "SUCCESS", "message": f"Launched {req.attack} attack on {req.target}"}

@app.post("/api/ota/deploy")
def deploy_ota_update(req: OTARequest):
    base_firmware = b"FIRMWARE_V2.1.0_BASE"
    new_firmware = f"FIRMWARE_{req.firmware_version}_RELEASE_PAYLOAD".encode("utf-8")
    
    if req.tampered:
        new_firmware = new_firmware + b"_TAMPERED_BY_MALICIOUS_ACTOR"

    delta = create_delta_patch(base_firmware, new_firmware)
    is_valid = verify_firmware_package(delta["delta_payload"], bytes.fromhex(delta["signature"]))
    
    if req.tampered or not is_valid:
        audit_logger.log_event("OTA_UPDATE_REJECTED", {"ecu": req.target_ecu, "version": req.firmware_version, "reason": "TAMPERED_SIGNATURE"})
        return {"status": "REJECTED", "message": "Ed25519 Signature Verification Failed! Update rejected by ECU."}
    
    audit_logger.log_event("OTA_UPDATE_APPLIED", {"ecu": req.target_ecu, "version": req.firmware_version, "delta_size": delta["delta_size"]})
    return {"status": "APPLIED", "message": f"Successfully applied signed OTA update {req.firmware_version} to {req.target_ecu}."}

@app.get("/api/audit")
def get_audit_logs():
    is_valid, errors = audit_logger.verify_chain_integrity()
    records = []
    if os.path.exists(audit_logger.log_path):
        with open(audit_logger.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
    return {
        "chain_valid": is_valid,
        "integrity_errors": errors,
        "total_records": len(records),
        "logs": list(reversed(records[-30:]))
    }

@app.get("/api/compliance/tara")
def get_tara_compliance_report():
    from tara_generator import generate_tara_report
    report_md = generate_tara_report(audit_logger)
    return {"report_markdown": report_md}
