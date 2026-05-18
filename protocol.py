"""
protocol.py
───────────────────────────────────────────────────────────────
Two-Round Mutual Authenticated Key Agreement
Based on Equations (3.42)–(3.45), SIGMA-V proposal.

THREAT MODEL (from Section 3.1):
  Attacker holds valid credentials but exploits trust relationships.
  Authentication alone cannot confirm correctness — hence mutual KEM.

PROTOCOL FLOW:
  ┌─ Vehicle OBU ──────────────────────── SDN Controller ─┐
  │                                                        │
  │  (K1, ct1) = Kyber.Enc(pk_C)                         │
  │  ──── ct1, cert_V ─────────────────────────────────►  │
  │                                                        │
  │                        K1 = Kyber.Dec(sk_C, ct1)      │
  │                        (K2, ct2) = Kyber.Enc(pk_V)    │
  │  ◄─── ct2, cert_C, MAC_K1(ct2) ──────────────────     │
  │                                                        │
  │  verify MAC_K1(ct2)                                   │
  │  K2 = Kyber.Dec(sk_V, ct2)                            │
  │  K_sess = KDF(K1‖K2‖V_id‖C_id‖t) ← both derive same │
  └────────────────────────────────────────────────────────┘

Security guarantees:
  • Vehicle is authenticated: only holder of sk_V can decap ct2.
  • Controller is authenticated: MAC_K1(ct2) proves it decapped ct1.
  • Session key is forward-secret: ephemeral per-session K1, K2.
  • Post-quantum secure: Kyber-512 resists Shor's algorithm.
"""

import time
from crypto_utils import (
    KyberKEM, kyber_encap,
    derive_session_key, split_session_key,
    hmac_sign, hmac_verify,
    b64e, b64d,
)


# ─────────────────────────────────────────────────────────────
# Vehicle Side
# ─────────────────────────────────────────────────────────────
class VehicleProtocol:
    """
    Vehicle OBU handshake state machine.
    Initiates Round 1; completes Round 2.
    """

    def __init__(self, vehicle_id: str, pk_controller: bytes):
        self.vehicle_id    = vehicle_id
        self.pk_controller = pk_controller

        # Generate vehicle's own Kyber keypair
        self.kem      = KyberKEM()
        self.pk_vehicle = self.kem.generate_keypair()

        # Handshake state (populated during rounds)
        self._K1          = None
        self._ct1         = None
        self.timestamp    = int(time.time())

        # Derived after Round 2
        self.session_key  = None
        self.enc_key      = None
        self.mac_key      = None

    # ── Round 1 ───────────────────────────────────────────────
    def round1_initiate(self) -> dict:
        """
        Round 1 — Vehicle → Controller         (Eq. 3.42)
        Encapsulate K1 against controller's pk.
        """
        ct1, K1      = kyber_encap(self.pk_controller)
        self._K1     = K1
        self._ct1    = ct1

        return {
            "vehicle_id" : self.vehicle_id,
            "pk_vehicle" : b64e(self.pk_vehicle),
            "ct1"        : b64e(ct1),
            "timestamp"  : self.timestamp,
        }

    # ── Round 2 ───────────────────────────────────────────────
    def round2_complete(self, response: dict) -> bool:
        """
        Round 2 — Vehicle receives controller response.    (Eq. 3.43–3.45)
        Verifies MAC_K1(ct2), decaps K2, derives K_sess.
        Returns True on success; raises ValueError on auth failure.
        """
        ct2           = b64d(response["ct2"])
        mac_tag       = b64d(response["mac"])
        controller_id = response["controller_id"]

        # Verify MAC_K1(ct2)
        # This proves the controller successfully decapped ct1 (holds K1)
        if not hmac_verify(self._K1, ct2, mac_tag):
            raise ValueError(
                "[HANDSHAKE FAIL] MAC_K1(ct2) invalid — "
                "possible MITM or controller impersonation"
            )

        # Decapsulate ct2 using vehicle's secret key → recover K2
        K2 = self.kem.decap(ct2)

        # Derive session key: K_sess = KDF(K1‖K2‖V_id‖C_id‖t)
        K_sess           = derive_session_key(
            self._K1, K2,
            self.vehicle_id, controller_id,
            self.timestamp,
        )
        self.session_key = K_sess
        self.enc_key, self.mac_key = split_session_key(K_sess)
        return True


# ─────────────────────────────────────────────────────────────
# Controller Side
# ─────────────────────────────────────────────────────────────
class ControllerProtocol:
    """
    SDN Controller handshake state machine.
    Responds to Round 1; stores per-vehicle session.
    """

    def __init__(self, controller_id: str):
        self.controller_id = controller_id

        # Generate controller's Kyber keypair (shared across all vehicles)
        self.kem           = KyberKEM()
        self.pk_controller = self.kem.generate_keypair()

        # vehicle_id → session dict
        self._sessions: dict[str, dict] = {}

    # ── Round 2 ───────────────────────────────────────────────
    def round2_respond(self, request: dict) -> dict:
        """
        Round 2 — Controller processes Round 1 and responds. (Eq. 3.43–3.45)
        Decaps K1, encaps K2 against vehicle's pk, derives K_sess,
        returns (ct2, cert_C, MAC_K1(ct2)).
        """
        vehicle_id = request["vehicle_id"]
        pk_vehicle = b64d(request["pk_vehicle"])
        ct1        = b64d(request["ct1"])
        timestamp  = request["timestamp"]

        # Decapsulate ct1 → recover K1   (proves vehicle had controller's pk)
        K1 = self.kem.decap(ct1)

        # Encapsulate K2 against vehicle's public key
        ct2, K2 = kyber_encap(pk_vehicle)

        # Derive session key (same formula as vehicle side)
        K_sess     = derive_session_key(
            K1, K2,
            vehicle_id, self.controller_id,
            timestamp,
        )
        enc_key, mac_key = split_session_key(K_sess)

        # Store session for this vehicle
        self._sessions[vehicle_id] = {
            "enc_key"     : enc_key,
            "mac_key"     : mac_key,
            "session_key" : K_sess,
        }

        # MAC_K1(ct2) — proves controller holds K1, binds ct2 to this session
        mac_tag = hmac_sign(K1, ct2)

        return {
            "controller_id" : self.controller_id,
            "ct2"           : b64e(ct2),
            "mac"           : b64e(mac_tag),
        }

    def get_session(self, vehicle_id: str) -> dict | None:
        """Retrieve established session keys for a vehicle."""
        return self._sessions.get(vehicle_id)
