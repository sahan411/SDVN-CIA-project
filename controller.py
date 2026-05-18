"""
controller.py
───────────────────────────────────────────────────────────────
SDN Controller — Message Receiver and Verifier
SIGMA-V — Information Security Course Project

Handles two message types post-handshake:

  1. BEACON  — Verifies HMAC-SHA256 tag.
               Reject on mismatch → LAF-DP detection trigger.

  2. METRIC  — Decrypts AES-256-GCM ciphertext, then verifies
               hash chain continuity.
               Reject on InvalidTag → ciphertext tampered.
               Reject on chain mismatch → replay or substitution.

Both checks implement the lightweight O(1) path from Section 3.3.8
of the SIGMA-V proposal, running per message arrival before any
routing rule is updated.
"""

import json
import hashlib
from crypto_utils import aes_gcm_decrypt, hmac_verify, hash_chain_step
from cryptography.exceptions import InvalidTag


class SDNController:
    """
    SDN Controller per-vehicle session handler.

    enc_key, mac_key derived from the shared Kyber session key,
    identical to those held by the paired VehicleOBU.
    """

    def __init__(self, controller_id: str, enc_key: bytes, mac_key: bytes,
                 vehicle_id: str):
        self.controller_id = controller_id
        self.enc_key       = enc_key
        self.mac_key       = mac_key
        self.vehicle_id    = vehicle_id

        # Hash chain seed mirrors vehicle side
        self._expected_chain: bytes = hashlib.sha256(vehicle_id.encode()).digest()
        self._last_seq: int         = 0
        self._last_beacon_seq: int  = -1

        # Running stats for viva demonstration
        self.accepted_beacons  = 0
        self.rejected_beacons  = 0
        self.accepted_metrics  = 0
        self.rejected_metrics  = 0

    # ── Beacon Handler ────────────────────────────────────────
    def receive_beacon(self, message: dict) -> tuple[bool, dict | str]:
        """
        Verify HMAC-SHA256 on beacon payload.

        Returns:
          (True,  parsed_beacon_dict)  — accepted
          (False, reason_string)       — rejected, reason logged
        """
        try:
            payload = bytes.fromhex(message["payload"])
            tag     = bytes.fromhex(message["hmac"])
        except (KeyError, ValueError) as e:
            self.rejected_beacons += 1
            return False, f"Malformed beacon message: {e}"

        if not hmac_verify(self.mac_key, payload, tag):
            self.rejected_beacons += 1
            return False, (
                "HMAC VERIFICATION FAILED — beacon rejected.\n"
                "    Possible cause: position falsification (LAF-DP) or tampering."
            )

        # Step 2: Sequence replay check — reject duplicate or out-of-order beacons
        parsed = json.loads(payload)
        seq    = parsed.get('seq', 0)
        if seq <= self._last_beacon_seq:
            self.rejected_beacons += 1
            return False, (
                f"SEQUENCE REPLAY — beacon seq #{seq} rejected "
                f"(last accepted: #{self._last_beacon_seq})."
            )

        self._last_beacon_seq = seq
        self.accepted_beacons += 1
        return True, parsed

    # ── Metric Handler ────────────────────────────────────────
    def receive_metric(self, message: dict) -> tuple[bool, dict | str]:
        """
        Decrypt AES-GCM metric and verify hash chain continuity.

        Returns:
          (True,  parsed_metric_dict)  — accepted
          (False, reason_string)       — rejected, reason logged

        Failure modes:
          • InvalidTag      → ciphertext was modified in transit
          • Chain mismatch  → metric was replayed or substituted
        """
        try:
            ct             = bytes.fromhex(message["ciphertext"])
            received_chain = bytes.fromhex(message["chain_hash"])
            aad            = message["aad"].encode()
            seq            = message.get("seq", 0)
        except (KeyError, ValueError) as e:
            self.rejected_metrics += 1
            return False, f"Malformed metric message: {e}"

        # Step 1: AES-GCM decryption + authentication tag check
        try:
            plaintext = aes_gcm_decrypt(self.enc_key, ct, aad)
        except InvalidTag:
            self.rejected_metrics += 1
            return False, (
                "AES-GCM TAG INVALID — metric rejected.\n"
                "    Ciphertext was modified after encryption (integrity violation)."
            )

        # Step 2: Hash chain verification
        # Controller recomputes expected chain from its own state
        expected_chain = hash_chain_step(self._expected_chain, plaintext)
        if expected_chain != received_chain:
            self.rejected_metrics += 1
            return False, (
                "HASH CHAIN BROKEN — metric rejected.\n"
                "    Possible cause: replayed metric or out-of-order substitution."
            )

        # All checks passed — advance chain state
        self._expected_chain = expected_chain
        self._last_seq       = seq
        self.accepted_metrics += 1
        return True, json.loads(plaintext)

    # ── Session Summary ───────────────────────────────────────
    def session_summary(self) -> dict:
        """Return counts for presentation/demo display."""
        return {
            "vehicle_id"       : self.vehicle_id,
            "accepted_beacons" : self.accepted_beacons,
            "rejected_beacons" : self.rejected_beacons,
            "accepted_metrics" : self.accepted_metrics,
            "rejected_metrics" : self.rejected_metrics,
            "last_beacon_seq"  : self._last_beacon_seq,
        }
