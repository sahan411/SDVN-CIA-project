"""
vehicle.py
───────────────────────────────────────────────────────────────
Vehicle On-Board Unit (OBU) — Message Sender
SIGMA-V — Information Security Course Project

Sends two message types post-handshake:

  1. BEACON  — HMAC-authenticated, plaintext position/speed.
               Eq. (3.32): B_i(t) = (x, v, t, HMAC_k(x‖v‖t))
               Lightweight: O(1) overhead per beacon.

  2. METRIC  — AES-256-GCM encrypted routing metric.
               Eq. (3.40–3.41): CT_M = AES-GCM.Enc(K_sess, M_i, AD_i)
               AD_i = (vehicle_id, timestamp) binds ciphertext to sender.
               Hash chain: h_i(t) = SHA256(M_i(t) ‖ h_i(t-1)) — Eq. (3.33)

Threat context: insider attacker who holds valid keys but reports
falsified data. HMAC proves source; AES-GCM + chain proves metric
has not been tampered or replayed since session establishment.
"""

import json
import time
import hashlib
from dataclasses import dataclass, asdict
from crypto_utils import aes_gcm_encrypt, hmac_sign, hash_chain_step


# ─────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────
@dataclass
class Beacon:
    """
    Raw state reported by vehicle to SDN controller.
    Contains position, speed, direction — used by controller
    to compute link attributes (distance, link lifetime, QoS).
    """
    vehicle_id : str
    position   : list        # [lat, lon] — GPS coordinates
    speed      : float       # m/s
    direction  : float       # degrees (0–360)
    timestamp  : int         # Unix epoch

    def serialize(self) -> bytes:
        return json.dumps(asdict(self), separators=(',', ':')).encode()


@dataclass
class RoutingMetric:
    """
    QoS metric computed by vehicle / reported to controller.
    In MS-DP attacks, these values are falsified by malicious vehicles.
    AES-GCM encryption ensures confidentiality; hash chain ensures
    any metric substitution or replay is detected.
    """
    vehicle_id : str
    hop_count  : int
    delay_ms   : float
    path_cost  : float
    timestamp  : int

    def serialize(self) -> bytes:
        return json.dumps(asdict(self), separators=(',', ':')).encode()


# ─────────────────────────────────────────────────────────────
# Vehicle OBU
# ─────────────────────────────────────────────────────────────
class VehicleOBU:
    """
    Vehicle On-Board Unit post-handshake message sender.

    enc_key: AES-256 key for metric encryption (from session key split).
    mac_key: HMAC key for beacon authentication (from session key split).
    Both derived via HKDF from the shared Kyber session secret.
    """

    def __init__(self, vehicle_id: str, enc_key: bytes, mac_key: bytes):
        self.vehicle_id = vehicle_id
        self.enc_key    = enc_key
        self.mac_key    = mac_key

        # Hash chain seed = SHA256(vehicle_id) — same on both sides
        self._chain_hash: bytes = hashlib.sha256(vehicle_id.encode()).digest()
        self._metric_count: int = 0

    # ── Beacon ────────────────────────────────────────────────
    def send_beacon(self, position: list, speed: float,
                    direction: float) -> dict:
        """
        Construct authenticated beacon.
        Returns wire message: {type, payload (hex), hmac (hex)}.

        Security: any bit-flip in payload invalidates HMAC at controller.
        Insider attacker who modifies GPS post-authentication is detected.
        """
        beacon  = Beacon(
            vehicle_id=self.vehicle_id,
            position=position,
            speed=speed,
            direction=direction,
            timestamp=int(time.time()),
        )
        payload = beacon.serialize()
        tag     = hmac_sign(self.mac_key, payload)

        return {
            "type"    : "beacon",
            "payload" : payload.hex(),
            "hmac"    : tag.hex(),
        }

    # ── Metric ────────────────────────────────────────────────
    def send_metric(self, hop_count: int, delay_ms: float,
                    path_cost: float) -> dict:
        """
        Construct encrypted routing metric message.
        Returns wire message: {type, ciphertext (hex), chain_hash (hex), aad}.

        Security:
          • AES-GCM tag covers ciphertext — any tamper → decryption failure.
          • AAD binds ciphertext to this vehicle and timestamp.
          • Hash chain covers plaintext — replay of old metric → chain mismatch.
        """
        self._metric_count += 1
        metric  = RoutingMetric(
            vehicle_id=self.vehicle_id,
            hop_count=hop_count,
            delay_ms=delay_ms,
            path_cost=path_cost,
            timestamp=int(time.time()),
        )
        payload = metric.serialize()

        # Advance hash chain: h(t) = SHA256(M(t) ‖ h(t-1))
        self._chain_hash = hash_chain_step(self._chain_hash, payload)

        # AAD = vehicle_id:timestamp — binds ciphertext to sender + time
        aad        = f"{self.vehicle_id}:{metric.timestamp}".encode()
        ciphertext = aes_gcm_encrypt(self.enc_key, payload, aad)

        return {
            "type"        : "metric",
            "ciphertext"  : ciphertext.hex(),
            "chain_hash"  : self._chain_hash.hex(),
            "aad"         : aad.decode(),
            "seq"         : self._metric_count,
        }
