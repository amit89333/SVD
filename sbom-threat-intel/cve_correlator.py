import json
import os
import sys

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "manifests", "vehicle1_sbom.json")

# Simulated / Static Threat Intel CVE Feed for Automotive Components
MOCK_CVE_DATABASE = [
    {
        "cve_id": "CVE-2023-45892",
        "affected_component": "openssl-1.1.1t",
        "severity": "CRITICAL",
        "score": 9.8,
        "description": "Buffer overflow in SSL handshake handling on automotive gateway ECUs allowing remote code execution."
    },
    {
        "cve_id": "CVE-2024-10928",
        "affected_component": "libcan-stack-1.0.2",
        "severity": "HIGH",
        "score": 8.1,
        "description": "Arbitration ID boundary checking vulnerability allowing frame injection bypass."
    },
    {
        "cve_id": "CVE-2022-38411",
        "affected_component": "busybox-1.31.1",
        "severity": "MEDIUM",
        "score": 6.5,
        "description": "Unauthenticated shell privilege escalation in infotainment domain shell environment."
    }
]

def scan_vehicle_sbom(manifest_filepath=MANIFEST_PATH) -> dict:
    """Scans vehicle SBOM manifest against CVE database feed and reports exposure."""
    if not os.path.exists(manifest_filepath):
        print(f"[SBOM Threat Intel] Manifest {manifest_filepath} not found.")
        return {"vehicle_id": "unknown", "vulnerabilities": []}

    with open(manifest_filepath, "r") as f:
        sbom_data = json.load(f)

    vehicle_id = sbom_data.get("vehicle_id", "vehicle-1")
    ecus = sbom_data.get("ecus", [])
    
    flagged_vulnerabilities = []
    
    for ecu in ecus:
        ecu_name = ecu.get("name", "Unknown ECU")
        components = ecu.get("components", [])
        
        for comp in components:
            for cve in MOCK_CVE_DATABASE:
                if cve["affected_component"].lower() in comp.lower():
                    flagged_vulnerabilities.append({
                        "ecu": ecu_name,
                        "component": comp,
                        "cve_id": cve["cve_id"],
                        "severity": cve["severity"],
                        "score": cve["score"],
                        "description": cve["description"]
                    })

    result = {
        "vehicle_id": vehicle_id,
        "total_ecus": len(ecus),
        "vulnerability_count": len(flagged_vulnerabilities),
        "vulnerabilities": flagged_vulnerabilities
    }
    return result

if __name__ == "__main__":
    report = scan_vehicle_sbom()
    print(f"=== SBOM Threat Intelligence Report for {report['vehicle_id']} ===")
    print(f"Total ECUs: {report['total_ecus']} | CVEs Found: {report['vulnerability_count']}")
    for v in report["vulnerabilities"]:
        print(f"  [{v['severity']}] {v['cve_id']} ({v['component']} on {v['ecu']}): {v['description']}")
