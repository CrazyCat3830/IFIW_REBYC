"""
קובץ זה אחראי על יצירת חבילת ראיות (Evidence Bundle)
עבור התראה שנבחרה על ידי המשתמש.

החבילה כוללת:
- קובץ PCAP עם החבילות הרלוונטיות
- קובץ JSON עם מטא-דאטה
- חתימת SHA256 לאימות שלמות הראיה
- רישום הפעולה ביומן Audit
"""
import hashlib  # Used to calculate SHA256 hashes for evidence integrity verification
import json  # Used to save metadata files
import os  # File and directory operations
from datetime import datetime, timezone

from scapy.layers.l2 import Ether  # Reconstructs Scapy packets from raw packet bytes
from scapy.utils import wrpcap  # Writes packets into a PCAP file

EVIDENCE_DIR = "evidence_bundles"


def sha256_file(path: str) -> str:
    """
    Calculates the SHA256 hash of a file.
    Used to verify that exported evidence was not modified.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        # Read the file in 1 MB chunks to avoid loading large files into memory
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def create_evidence_bundle(db, *, user_email: str, incident_id: int, max_packets: int = 5000):
    """
    Creates a forensic evidence package for a selected alert.

    The package includes:
    - Reconstructed PCAP file
    - Metadata JSON file
    - SHA256 integrity hash
    - Audit log record
    """
    # Create the evidence directory if it does not already exist
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    # Find the packet that triggered the selected alert
    packet_id = db.get_alert_packet_id(incident_id)
    # Cannot export evidence if the alert has no associated packet
    if packet_id is None:
        raise ValueError("Alert not found or has no anchor packet")
    # Retrieve packets related to the incident from the database
    rows = db.get_packet_bytes_before(packet_id, limit=max_packets)
    packets = []
    for raw_bytes in rows:
        if not raw_bytes:
            continue
        try:
            # Reconstruct a Scapy packet object from raw bytes stored in the database
            packets.append(Ether(raw_bytes))
        except Exception:
            # Skip corrupted or unparsable packet data
            continue
    # Generate a timestamp for unique evidence file names
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    pcap_path = os.path.join(EVIDENCE_DIR, f"evidence_{incident_id}_{ts}.pcap")
    # Export packets into a PCAP file for forensic analysis
    wrpcap(pcap_path, list(reversed(packets)))
    # Calculate file hash to verify evidence integrity
    sha = sha256_file(pcap_path)
    # Store metadata describing the exported evidence
    meta = {
        "incident_id": incident_id,
        "packet_count": len(packets),
        "pcap_path": pcap_path,
        "sha256": sha,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    # Save metadata next to the PCAP file
    meta_path = pcap_path.replace(".pcap", ".json")
    with open(meta_path, "w", encoding="utf-8") as f:
        # Write metadata in a human-readable JSON format
        json.dump(meta, f, indent=2, ensure_ascii=False)

    db.insert_audit(
        user_email=user_email,
        action="FORENSICS_EXPORT",
        params_json=json.dumps({"incident_id": incident_id}),
        created_at=meta["created_at"],
        artifact_path=pcap_path,
        artifact_sha256=sha,  # Store hash in audit log for chain-of-custody verification
    )

    return pcap_path, meta_path, sha
