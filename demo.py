"""
demo.py
───────────────────────────────────────────────────────────────
SIGMA-V — Information Security Course Project
Post-Quantum Secure Communication Between Vehicles and SDN Controllers

University of Ruhuna — Dept. of Electrical and Information Engineering
Group G5 | Supervisor: Mr. Nilmantha Wijesekara

Demonstrates (single-process, no network required):
  Phase 1 — Kyber-512 keypair generation (Vehicle + Controller)
  Phase 2 — Two-round mutual authenticated key agreement
  Phase 3 — Authenticated beacon transmission (HMAC-SHA256)
  Phase 4 — Encrypted routing metric transmission (AES-256-GCM)
  Phase 5 — Attack: tampered beacon → HMAC rejection  [LAF-DP]
  Phase 6 — Attack: replayed metric  → chain rejection [MS-DP]
  Phase 7 — Session summary and security property mapping

Run:
  python demo.py
"""

import copy
import sys

from protocol   import VehicleProtocol, ControllerProtocol
from vehicle    import VehicleOBU
from controller import SDNController

# ─────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────
W = 68

def section(title: str):
    print(f"\n{'─' * W}")
    print(f"  {title}")
    print(f"{'─' * W}")

def ok(msg: str):
    print(f"  \033[92m✓\033[0m  {msg}")

def fail(msg: str):
    for i, line in enumerate(msg.strip().split('\n')):
        prefix = "  \033[91m✗\033[0m  " if i == 0 else "       "
        print(f"{prefix}{line.strip()}")

def info(msg: str):
    print(f"  ►  {msg}")

def sub(msg: str):
    print(f"       {msg}")

def header():
    print("\n" + "═" * W)
    print("  POST-QUANTUM SECURE V2C COMMUNICATION — SIGMA-V")
    print("  Information Security Course Project | Group G5")
    print("  University of Ruhuna — EIE Department")
    print("═" * W)

# ─────────────────────────────────────────────────────────────
# Phase 1 — Key Generation
# ─────────────────────────────────────────────────────────────
def phase1_keygen() -> tuple[ControllerProtocol, VehicleProtocol]:
    section("PHASE 1 — Kyber-512 Keypair Generation")

    info("Algorithm  : Kyber-512 (ML-KEM, NIST FIPS 203)")
    info("Security   : 128-bit post-quantum, resists Shor's algorithm")
    print()

    ctrl = ControllerProtocol(controller_id="C1")
    info(f"Controller C1 keypair generated")
    sub(f"pk_C  (hex, first 32B) : {ctrl.pk_controller[:32].hex()}")

    veh = VehicleProtocol(vehicle_id="V1", pk_controller=ctrl.pk_controller)
    info(f"Vehicle    V1 keypair generated")
    sub(f"pk_V  (hex, first 32B) : {veh.pk_vehicle[:32].hex()}")

    ok("Both parties hold independent Kyber-512 keypairs")
    return ctrl, veh


# ─────────────────────────────────────────────────────────────
# Phase 2 — Two-Round Handshake
# ─────────────────────────────────────────────────────────────
def phase2_handshake(ctrl: ControllerProtocol,
                     veh: VehicleProtocol) -> tuple[dict, dict]:
    section("PHASE 2 — Two-Round Mutual Key Agreement  (Eq. 3.42–3.45)")

    # Round 1
    info("Round 1: Vehicle → Controller")
    r1 = veh.round1_initiate()
    sub(f"ct1           (first 32B) : {r1['ct1'][:44]}...")
    sub(f"Vehicle cert  (ID)        : {r1['vehicle_id']}")
    sub(f"Timestamp                 : {r1['timestamp']}")
    print()

    # Round 2
    info("Round 2: Controller → Vehicle")
    r2 = ctrl.round2_respond(r1)
    sub(f"ct2           (first 32B) : {r2['ct2'][:44]}...")
    sub(f"MAC_K1(ct2)   (first 32B) : {r2['mac'][:44]}...")
    print()

    # Vehicle completes
    veh.round2_complete(r2)

    # Verify both sides hold identical session key
    ctrl_sess = ctrl.get_session("V1")
    if ctrl_sess["session_key"] == veh.session_key:
        ok("MAC_K1(ct2) verified by Vehicle — controller is authentic")
        ok("Session keys MATCH on both sides")
        sub(f"K_sess  (hex, first 32B) : {veh.session_key[:32].hex()}")
        sub(f"enc_key (hex, first 16B) : {veh.enc_key[:16].hex()}")
        sub(f"mac_key (hex, first 16B) : {veh.mac_key[:16].hex()}")
    else:
        fail("Session key MISMATCH — handshake error")
        sys.exit(1)

    return ctrl_sess, r1


# ─────────────────────────────────────────────────────────────
# Phase 3 — Authenticated Beacon
# ─────────────────────────────────────────────────────────────
def phase3_beacon(obu: VehicleOBU,
                  rx: SDNController) -> dict:
    section("PHASE 3 — Authenticated Beacon Transmission  (Eq. 3.32)")

    info("Mechanism : HMAC-SHA256(mac_key, beacon_payload)")
    info("Purpose   : Detect GPS/position falsification (LAF-DP)")
    print()

    beacon_msg = obu.send_beacon(
        position  = [6.9271, 79.8612],  # Colombo, Sri Lanka
        speed     = 13.9,                # 50 km/h in m/s
        direction = 270.0,
    )
    info("Vehicle V1 sends beacon:")
    sub(f"position  : [6.9271, 79.8612]   (Colombo)")
    sub(f"speed     : 13.9 m/s  (50 km/h)")
    sub(f"direction : 270.0°  (westbound)")
    sub(f"HMAC tag  : {beacon_msg['hmac'][:32]}...")
    print()

    ok_flag, result = rx.receive_beacon(beacon_msg)
    if ok_flag:
        ok(f"Controller C1 accepted beacon")
        sub(f"Verified position : {result['position']}")
        sub(f"Verified speed    : {result['speed']} m/s")
    else:
        fail(result)

    return beacon_msg


# ─────────────────────────────────────────────────────────────
# Phase 4 — Encrypted Metric
# ─────────────────────────────────────────────────────────────
def phase4_metric(obu: VehicleOBU,
                  rx: SDNController) -> dict:
    section("PHASE 4 — Encrypted Routing Metric  (Eq. 3.40–3.41, 3.33)")

    info("Mechanism : AES-256-GCM(enc_key, metric, AAD) + hash chain")
    info("Purpose   : Confidentiality + integrity of QoS metrics (MS-DP)")
    print()

    metric_msg = obu.send_metric(hop_count=2, delay_ms=18.4, path_cost=0.31)
    info("Vehicle V1 sends routing metric:")
    sub(f"hop_count : 2")
    sub(f"delay_ms  : 18.4 ms")
    sub(f"path_cost : 0.31")
    sub(f"Ciphertext (first 32B) : {metric_msg['ciphertext'][:64]}...")
    sub(f"Chain hash (first 16B) : {metric_msg['chain_hash'][:32]}...")
    sub(f"AAD                    : {metric_msg['aad']}")
    print()

    ok_flag, result = rx.receive_metric(metric_msg)
    if ok_flag:
        ok("Controller C1 decrypted and verified metric")
        sub(f"hop_count : {result['hop_count']}")
        sub(f"delay_ms  : {result['delay_ms']} ms")
        sub(f"path_cost : {result['path_cost']}")
    else:
        fail(result)

    return metric_msg


# ─────────────────────────────────────────────────────────────
# Phase 5 — Attack: Tampered Beacon (LAF-DP)
# ─────────────────────────────────────────────────────────────
def phase5_attack_beacon(obu: VehicleOBU, rx: SDNController,
                          beacon_msg: dict):
    section("PHASE 5 — ATTACK SCENARIO: Tampered Beacon  (LAF-DP)")

    info("Scenario : Attacker intercepts beacon, falsifies GPS position")
    info("In SIGMA-V : Signature S1 (Position-Speed Inconsistency)")
    print()

    tampered = copy.deepcopy(beacon_msg)
    raw      = bytes.fromhex(tampered["payload"])

    # Flip byte at offset 20 — corrupts position field
    tampered_payload     = raw[:20] + bytes([raw[20] ^ 0xFF]) + raw[21:]
    tampered["payload"]  = tampered_payload.hex()

    info(f"Original  byte[20] : 0x{raw[20]:02x}")
    info(f"Tampered  byte[20] : 0x{tampered_payload[20]:02x}  (XOR 0xFF)")
    print()

    ok_flag, result = rx.receive_beacon(tampered)
    if not ok_flag:
        fail(result)
        ok("Attack BLOCKED — falsified beacon did not reach routing pipeline")
    else:
        print("  [!] SECURITY FAILURE — tampered beacon was accepted")


# ─────────────────────────────────────────────────────────────
# Phase 6 — Attack: Replayed Metric (MS-DP)
# ─────────────────────────────────────────────────────────────
def phase6_attack_replay(rx: SDNController, metric_msg: dict):
    section("PHASE 6 — ATTACK SCENARIO: Replayed Metric  (MS-DP)")

    info("Scenario : Attacker replays a previously captured metric")
    info("In SIGMA-V : Hash chain (Eq. 3.33) detects stale replay")
    print()
    info("Attacker re-transmits metric_msg from Phase 4 ...")
    print()

    ok_flag, result = rx.receive_metric(metric_msg)
    if not ok_flag:
        fail(result)
        ok("Attack BLOCKED — replayed metric rejected by hash chain")
    else:
        print("  [!] SECURITY FAILURE — replayed metric was accepted")


# ─────────────────────────────────────────────────────────────
# Phase 7 — Summary
# ─────────────────────────────────────────────────────────────
def phase7_summary(rx: SDNController):
    section("PHASE 7 — Security Properties and Session Summary")

    print()
    print("  Security Property Mapping:")
    print(f"  {'─' * 62}")
    props = [
        ("Confidentiality",   "AES-256-GCM encrypted metrics (attacker sees only ciphertext)"),
        ("Integrity",         "HMAC-SHA256 on beacons + SHA256 hash chain on metrics"),
        ("Authentication",    "Mutual Kyber-512 key agreement — both parties verified"),
        ("Non-Repudiation",   "MAC_K1(ct2) binds controller identity to session key"),
        ("Post-Quantum Sec.", "Kyber-512 resists quantum adversary (Shor's algorithm)"),
    ]
    for prop, mechanism in props:
        print(f"  \033[92m✓\033[0m  {prop:<22} {mechanism}")

    print()
    summary = rx.session_summary()
    print("  Session Statistics:")
    print(f"  {'─' * 62}")
    print(f"  Vehicle                : {summary['vehicle_id']}")
    print(f"  Beacons accepted       : {summary['accepted_beacons']}")
    print(f"  Beacons rejected       : {summary['rejected_beacons']}  ← tampered blocked")
    print(f"  Metrics  accepted      : {summary['accepted_metrics']}")
    print(f"  Metrics  rejected      : {summary['rejected_metrics']}  ← replay blocked")

    print(f"\n{'═' * W}\n")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────
def main():
    header()

    # Phase 1: Key generation
    ctrl_proto, veh_proto = phase1_keygen()

    # Phase 2: Handshake
    ctrl_sess, _ = phase2_handshake(ctrl_proto, veh_proto)

    # Construct post-handshake OBU and controller receiver
    obu = VehicleOBU(
        vehicle_id = "V1",
        enc_key    = veh_proto.enc_key,
        mac_key    = veh_proto.mac_key,
    )
    rx = SDNController(
        controller_id = "C1",
        enc_key       = ctrl_sess["enc_key"],
        mac_key       = ctrl_sess["mac_key"],
        vehicle_id    = "V1",
    )

    # Phase 3: Beacon
    beacon_msg = phase3_beacon(obu, rx)

    # Phase 4: Metric
    metric_msg = phase4_metric(obu, rx)

    # Phase 5: Tamper attack
    phase5_attack_beacon(obu, rx, beacon_msg)

    # Phase 6: Replay attack
    phase6_attack_replay(rx, metric_msg)

    # Phase 7: Summary
    phase7_summary(rx)


if __name__ == "__main__":
    main()
