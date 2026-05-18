"""
crypto_utils.py — Cryptographic primitives for PQ-Secure V2C Communication
SIGMA-V | Information Security Course Project | University of Ruhuna EIE

Primitives:
  Kyber-512    NIST ML-KEM (FIPS 203) via kyber-py
  AES-256-GCM  Authenticated encryption for routing metrics
  HMAC-SHA256  Beacon authentication        (Eq. 3.32)
  HKDF-SHA256  Session key derivation       (Eq. 3.45)
  SHA-256 chain Metric integrity chaining   (Eq. 3.33)
"""

import os, hmac as _hmac, hashlib, base64
from kyber_py.kyber import Kyber512
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

AES_KEY_LEN  = 32
HMAC_KEY_LEN = 32
NONCE_LEN    = 12
SESSION_LEN  = AES_KEY_LEN + HMAC_KEY_LEN  # 64 bytes


class KyberKEM:
    """Persistent Kyber-512 KEM: keypair generation + decapsulation."""

    def __init__(self, secret_key: bytes = None):
        self._pk: bytes = None
        self._sk: bytes = secret_key

    def generate_keypair(self) -> bytes:
        self._pk, self._sk = Kyber512.keygen()
        return self._pk

    @property
    def public_key(self) -> bytes:
        return self._pk

    def export_secret_key(self) -> bytes:
        return self._sk

    def decap(self, ciphertext: bytes) -> bytes:
        return Kyber512.decaps(self._sk, ciphertext)


def kyber_encap(peer_pk: bytes) -> tuple:
    """Ephemeral encapsulation. Returns (ciphertext, shared_secret)."""
    shared_secret, ciphertext = Kyber512.encaps(peer_pk)
    return ciphertext, shared_secret


def derive_session_key(K1: bytes, K2: bytes,
                       vehicle_id: str, controller_id: str,
                       timestamp: int) -> bytes:
    """K_sess = KDF(K1‖K2‖V_id‖C_id‖t)  — Eq. (3.45)"""
    info = f"{vehicle_id}:{controller_id}:{timestamp}".encode()
    return HKDF(algorithm=hashes.SHA256(), length=SESSION_LEN,
                salt=None, info=info).derive(K1 + K2)


def split_session_key(K_sess: bytes) -> tuple:
    return K_sess[:AES_KEY_LEN], K_sess[AES_KEY_LEN:]


def aes_gcm_encrypt(enc_key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(enc_key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(enc_key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(enc_key).decrypt(data[:NONCE_LEN], data[NONCE_LEN:], aad)


def hmac_sign(mac_key: bytes, message: bytes) -> bytes:
    return _hmac.new(mac_key, message, hashlib.sha256).digest()


def hmac_verify(mac_key: bytes, message: bytes, tag: bytes) -> bool:
    return _hmac.compare_digest(hmac_sign(mac_key, message), tag)


def hash_chain_step(prev_hash: bytes, metric_bytes: bytes) -> bytes:
    """h_i(t) = SHA256(M_i(t) ‖ h_i(t-1))  — Eq. (3.33)"""
    return hashlib.sha256(metric_bytes + prev_hash).digest()


def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s)
