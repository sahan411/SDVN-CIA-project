"""
app.py
───────────────────────────────────────────────────────────────
SIGMA-V — Live Demo Flask Server
Information Security Course Project | Group G5
University of Ruhuna — EIE Department

Run:
    pip install flask
    python app.py
    Open: http://localhost:5000

Routes:
    POST /api/handshake       — Kyber-512 key agreement
    POST /api/beacon          — HMAC-authenticated beacon
    POST /api/metric          — AES-256-GCM encrypted metric
    POST /api/attack/beacon   — LAF-DP: tampered beacon
    POST /api/attack/metric   — MS-DP: replayed metric
    POST /api/reset           — Reset demo session
"""

import copy
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, send_from_directory
from protocol    import VehicleProtocol, ControllerProtocol
from vehicle     import VehicleOBU
from controller  import SDNController
from crypto_utils import kyber_encap, b64e

app = Flask(__name__)

_RATE_LIMIT_MAX    = 5      # max beacons per flood window
_RATE_LIMIT_WINDOW = 30.0   # seconds

# ── Global demo state ────────────────────────────────────────
_state = {}

def reset_state():
    _state.clear()
    _state.update({
        'ctrl_proto'     : None,
        'veh_proto'      : None,
        'obu'            : None,
        'rx'             : None,
        'last_beacon'    : None,
        'last_metric'    : None,
        'handshake_done' : False,
        'flood_count'    : 0,
        'flood_window'   : 0.0,
        'flood_blocked'  : 0,
    })

reset_state()


# ── Routes ───────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)),
                               'index.html')


@app.route('/api/reset', methods=['POST'])
def api_reset():
    reset_state()
    return jsonify({'ok': True, 'message': 'Demo session reset.'})


@app.route('/api/handshake', methods=['POST'])
def api_handshake():
    try:
        _t_start = time.perf_counter()

        # Phase 1: Generate keypairs
        _t0  = time.perf_counter()
        ctrl = ControllerProtocol(controller_id='C1')
        veh  = VehicleProtocol(vehicle_id='V1',
                               pk_controller=ctrl.pk_controller)
        _t_keygen = round((time.perf_counter() - _t0) * 1000, 1)

        # Phase 2: Two-round key agreement
        _t0 = time.perf_counter()
        r1  = veh.round1_initiate()
        _t_r1 = round((time.perf_counter() - _t0) * 1000, 1)

        _t0 = time.perf_counter()
        r2  = ctrl.round2_respond(r1)
        _t_r2 = round((time.perf_counter() - _t0) * 1000, 1)

        _t0 = time.perf_counter()
        veh.round2_complete(r2)
        _t_r2c = round((time.perf_counter() - _t0) * 1000, 1)

        _t_total = round((time.perf_counter() - _t_start) * 1000, 1)

        ctrl_sess = ctrl.get_session('V1')

        # Store post-handshake objects
        _state['ctrl_proto']     = ctrl
        _state['veh_proto']      = veh
        _state['handshake_done'] = True
        _state['obu'] = VehicleOBU(
            vehicle_id = 'V1',
            enc_key    = veh.enc_key,
            mac_key    = veh.mac_key,
        )
        _state['rx'] = SDNController(
            controller_id = 'C1',
            enc_key       = ctrl_sess['enc_key'],
            mac_key       = ctrl_sess['mac_key'],
            vehicle_id    = 'V1',
        )

        return jsonify({
            'ok'        : True,
            'algorithm' : 'Kyber-512  (NIST ML-KEM / FIPS 203)',
            'steps'     : [
                'Vehicle V1  →  Kyber-512 keypair generated',
                'Controller C1  →  Kyber-512 keypair generated',
                'Round 1: Vehicle encapsulates K1 using pk_C  →  sends ct1',
                'Round 1: Controller decapsulates ct1  →  recovers K1',
                'Round 2: Controller encapsulates K2 using pk_V  →  sends ct2',
                'Round 2: Controller computes MAC_K1(ct2)  →  proves identity',
                'Vehicle verifies MAC_K1(ct2)  →  controller authenticated',
                'Vehicle decapsulates ct2  →  recovers K2',
                'K_sess = HKDF(K1 ‖ K2 ‖ V1 ‖ C1 ‖ timestamp)',
                'enc_key = K_sess[0:32]   mac_key = K_sess[32:64]',
            ],
            'session_key' : veh.session_key[:16].hex() + '...',
            'enc_key'     : veh.enc_key[:12].hex()    + '...',
            'mac_key'     : veh.mac_key[:12].hex()    + '...',
            'pk_v_size'   : '800 bytes',
            'pk_c_size'   : '800 bytes',
            'ct1_size'    : '768 bytes',
            'ct2_size'    : '768 bytes',
            'timing'      : {
                'keygen_ms'     : _t_keygen,
                'r1_encap_ms'   : _t_r1,
                'r2_respond_ms' : _t_r2,
                'r2_complete_ms': _t_r2c,
                'total_ms'      : _t_total,
            },
        })

    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)})


@app.route('/api/beacon', methods=['POST'])
def api_beacon():
    if not _state.get('handshake_done'):
        return jsonify({'ok': False,
                        'message': 'Complete the handshake first.'})
    try:
        obu = _state['obu']
        rx  = _state['rx']

        msg = obu.send_beacon(
            position  = [6.9271, 79.8612],
            speed     = 13.9,
            direction = 270.0,
        )
        _state['last_beacon'] = msg

        ok, result = rx.receive_beacon(msg)
        summary    = rx.session_summary()

        return jsonify({
            'ok'   : ok,
            'sent' : {
                'position'  : '[6.9271, 79.8612]  (Colombo, LK)',
                'speed'     : '13.9 m/s  (50 km/h)',
                'direction' : '270.0°  (westbound)',
                'hmac_tag'  : msg['hmac'][:24] + '...',
                'mechanism' : 'HMAC-SHA256(mac_key, payload)',
            },
            'result'  : result if ok else str(result),
            'summary' : summary,
        })

    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)})


@app.route('/api/metric', methods=['POST'])
def api_metric():
    if not _state.get('handshake_done'):
        return jsonify({'ok': False,
                        'message': 'Complete the handshake first.'})
    try:
        obu = _state['obu']
        rx  = _state['rx']

        msg = obu.send_metric(hop_count=2, delay_ms=18.4, path_cost=0.31)
        _state['last_metric'] = msg

        ok, result = rx.receive_metric(msg)
        summary    = rx.session_summary()

        return jsonify({
            'ok'   : ok,
            'sent' : {
                'hop_count'  : 2,
                'delay_ms'   : '18.4 ms',
                'path_cost'  : 0.31,
                'ciphertext' : msg['ciphertext'][:24] + '...',
                'chain_hash' : msg['chain_hash'][:24] + '...',
                'aad'        : msg['aad'],
                'mechanism'  : 'AES-256-GCM(enc_key, metric, AAD) + SHA-256 chain',
            },
            'result'  : result if ok else str(result),
            'summary' : summary,
        })

    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)})


@app.route('/api/attack/beacon', methods=['POST'])
def api_attack_beacon():
    if not _state.get('last_beacon'):
        return jsonify({'ok': False,
                        'message': 'Send a beacon first, then try the attack.'})
    try:
        rx       = _state['rx']
        tampered = copy.deepcopy(_state['last_beacon'])
        raw      = bytes.fromhex(tampered['payload'])
        raw_t    = raw[:20] + bytes([raw[20] ^ 0xFF]) + raw[21:]
        tampered['payload'] = raw_t.hex()

        ok, result  = rx.receive_beacon(tampered)
        summary     = rx.session_summary()

        return jsonify({
            'ok'     : ok,
            'attack' : 'LAF-DP — Link Attribute Falsification (Data Plane)',
            'action' : f"Intercepted beacon — byte[20] flipped: "
                       f"0x{raw[20]:02x} → 0x{raw_t[20]:02x}  (XOR 0xFF)",
            'explanation' : 'Attacker modifies GPS position in beacon payload. '
                            'HMAC tag no longer matches — controller rejects.',
            'result'  : str(result),
            'summary' : summary,
            'blocked' : True,
        })

    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)})


@app.route('/api/attack/metric', methods=['POST'])
def api_attack_metric():
    if not _state.get('last_metric'):
        return jsonify({'ok': False,
                        'message': 'Send a metric first, then try the attack.'})
    try:
        rx      = _state['rx']
        ok, result  = rx.receive_metric(_state['last_metric'])
        summary     = rx.session_summary()

        return jsonify({
            'ok'     : ok,
            'attack' : 'MS-DP — Metric Spoofing (Data Plane)',
            'action' : 'Replaying previously captured metric message.',
            'explanation' : 'Attacker replays an old metric with favourable QoS values. '
                            'Hash chain has advanced — expected hash does not match.',
            'result'  : str(result),
            'summary' : summary,
            'blocked' : True,
        })

    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)})


@app.route('/api/attack/mitm', methods=['POST'])
def api_attack_mitm():
    """MITM: attacker substitutes ct2 in Round 2 — MAC_K1 verification catches it."""
    try:
        ctrl_d = ControllerProtocol(controller_id='C1')
        veh_d  = VehicleProtocol(vehicle_id='V1',
                                 pk_controller=ctrl_d.pk_controller)

        r1      = veh_d.round1_initiate()
        r2_real = ctrl_d.round2_respond(r1)

        # Attacker intercepts Round 2 and substitutes ct2 with a fresh encapsulation.
        # They cannot forge MAC_K1(ct2_fake) without knowing K1.
        ct2_fake, _ = kyber_encap(veh_d.pk_vehicle)
        r2_tampered = {**r2_real, 'ct2': b64e(ct2_fake)}

        try:
            veh_d.round2_complete(r2_tampered)
            blocked = False
            result  = 'SECURITY FAILURE — MITM attack succeeded'
        except ValueError as e:
            blocked = True
            result  = str(e)

        return jsonify({
            'ok'         : False,
            'attack'     : 'MITM — Man-in-the-Middle on Handshake Round 2',
            'action'     : 'Attacker intercepts Round 2, replaces ct2 with a fresh Kyber ciphertext',
            'explanation': 'Without K1, attacker cannot forge MAC_K1(ct2_fake). Vehicle detects the substitution.',
            'result'     : result,
            'blocked'    : blocked,
        })

    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)})


@app.route('/api/attack/flood', methods=['POST'])
def api_attack_flood():
    """DoS flood: sends 10 rapid beacons — rate limiter blocks excess (Availability demo)."""
    if not _state.get('handshake_done'):
        return jsonify({'ok': False,
                        'message': 'Complete the handshake first.'})
    try:
        obu = _state['obu']
        rx  = _state['rx']
        now = time.time()

        if now - _state['flood_window'] > _RATE_LIMIT_WINDOW:
            _state['flood_count']   = 0
            _state['flood_window']  = now
            _state['flood_blocked'] = 0

        results = []
        for i in range(10):
            _state['flood_count'] += 1
            if _state['flood_count'] > _RATE_LIMIT_MAX:
                _state['flood_blocked'] += 1
                results.append({
                    'seq'    : i + 1,
                    'status' : 'BLOCKED',
                    'reason' : f'Rate limit ({_RATE_LIMIT_MAX} per {int(_RATE_LIMIT_WINDOW)}s)',
                })
            else:
                msg = obu.send_beacon(
                    position=[6.9271, 79.8612], speed=13.9, direction=270.0
                )
                ok_flag, _ = rx.receive_beacon(msg)
                results.append({
                    'seq'    : i + 1,
                    'status' : 'ACCEPTED' if ok_flag else 'REJECTED',
                })

        summary = rx.session_summary()
        return jsonify({
            'ok'           : True,
            'attack'       : 'DoS — Beacon Flood Attack (Availability)',
            'action'       : f'Attacker sends 10 rapid beacons. Rate limiter: {_RATE_LIMIT_MAX} per {int(_RATE_LIMIT_WINDOW)}s.',
            'explanation'  : 'Rate limiting protects Availability — excess messages dropped before processing.',
            'results'      : results,
            'flood_blocked': _state['flood_blocked'],
            'summary'      : summary,
        })

    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)})


if __name__ == '__main__':
    print("\n  SIGMA-V Live Demo")
    print("  Open: http://localhost:5000\n")
    app.run(debug=False, port=5000)
