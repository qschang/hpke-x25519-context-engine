from __future__ import annotations

import hashlib
import hmac
import os
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

_KEM_ID = 0x20
_KDF_ID = 1
def _suite_id(aead_id: int) -> bytes:
    return b"HPKE" + _KEM_ID.to_bytes(2, "big") + _KDF_ID.to_bytes(2, "big") + aead_id.to_bytes(2, "big")
_KEM_SUITE_ID = b"KEM" + _KEM_ID.to_bytes(2, "big")
_VERSION = b"HPKE-v1"
_MAX_SEQ = (1 << 96) - 1


def _i2osp(n: int, length: int) -> bytes:
    if n < 0 or n >= 1 << (8 * length):
        raise ValueError("integer out of range")
    return n.to_bytes(length, "big")


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0 or length > 255 * 32:
        raise ValueError("HKDF length out of range")
    out = bytearray()
    t = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out.extend(t)
    return bytes(out[:length])


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite: bytes) -> bytes:
    return _extract(salt, _VERSION + suite + label + ikm)


def _labeled_expand(prk: bytes, label: bytes, info: bytes, length: int, suite: bytes) -> bytes:
    return _expand(prk, _i2osp(length, 2) + _VERSION + suite + label + info, length)


def _raw_public(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _check32(x: bytes, label: str) -> bytes:
    if not isinstance(x, (bytes, bytearray)) or len(x) != 32:
        raise ValueError(f"invalid {label}")
    return bytes(x)


def serialize_public_key(raw: bytes) -> bytes:
    return _check32(raw, "public key")


def deserialize_public_key(data: bytes) -> bytes:
    return _check32(data, "public key")


def serialize_private_key(raw: bytes) -> bytes:
    return _check32(raw, "private key")


def deserialize_private_key(data: bytes) -> bytes:
    return _check32(data, "private key")


def _pub(raw: bytes) -> X25519PublicKey:
    try:
        return X25519PublicKey.from_public_bytes(_check32(raw, "public key"))
    except Exception:
        raise ValueError("invalid public key") from None


def _priv(raw: bytes) -> X25519PrivateKey:
    try:
        return X25519PrivateKey.from_private_bytes(_check32(raw, "private key"))
    except Exception:
        raise ValueError("invalid private key") from None


def _dh(sk: X25519PrivateKey, pk: X25519PublicKey) -> bytes:
    try:
        out = sk.exchange(pk)
    except Exception:
        raise ValueError("invalid DH input") from None
    if out == b"\x00" * 32:
        raise ValueError("invalid DH input")
    return out


def _validate(mode: int, aead_id: int, psk: bytes | None, psk_id: bytes, sk_s: bytes | None, pk_s: bytes | None) -> None:
    if mode not in (0, 1, 2, 3) or aead_id not in (1, 3, 0xFFFF):
        raise ValueError("unsupported HPKE suite")
    if not isinstance(psk_id, bytes):
        raise ValueError("invalid psk_id")
    has_psk, has_id = psk is not None, len(psk_id) > 0
    if (mode in (1, 3)) != has_psk or (mode in (1, 3)) != has_id:
        raise ValueError("invalid PSK inputs")
    if mode in (2, 3):
        if sk_s is not None and len(sk_s) != 32:
            raise ValueError("invalid sender key")
        if pk_s is not None and len(pk_s) != 32:
            raise ValueError("invalid sender key")
    elif sk_s is not None or pk_s is not None:
        raise ValueError("unexpected authentication key")
    if psk is not None and (not isinstance(psk, bytes) or len(psk) == 0):
        raise ValueError("invalid PSK")


def _key_schedule(mode: int, aead_id: int, shared_secret: bytes, info: bytes, psk: bytes | None, psk_id: bytes):
    psk_b = psk or b""
    suite = _suite_id(aead_id)
    psk_id_hash = _labeled_extract(b"", b"psk_id_hash", psk_id, suite)
    info_hash = _labeled_extract(b"", b"info_hash", info, suite)
    ksc = bytes([mode]) + psk_id_hash + info_hash
    secret = _labeled_extract(shared_secret, b"secret", psk_b, suite)
    if aead_id == 1:
        nk, nn = 16, 12
    elif aead_id == 3:
        nk, nn = 32, 12
    else:
        nk, nn = 0, 0
    key = _labeled_expand(secret, b"key", ksc, nk, suite) if nk else b""
    nonce = _labeled_expand(secret, b"base_nonce", ksc, nn, suite) if nn else b""
    exp = _labeled_expand(secret, b"exp", ksc, 32, suite)
    return key, nonce, exp, nn


class Context:
    def __init__(self, key: bytes, base_nonce: bytes, exporter_secret: bytes, aead_id: int, sender: bool, nn: int):
        self._key, self._base_nonce, self._exporter = bytes(key), bytes(base_nonce), bytes(exporter_secret)
        self._aead_id, self._sender, self._nn, self._seq, self._failed = aead_id, sender, nn, 0, False

    @property
    def seq(self) -> int:
        return self._seq

    @property
    def aead_id(self) -> int:
        return self._aead_id

    def _usable(self) -> None:
        if self._failed:
            raise ValueError("context unavailable")

    def _nonce(self) -> bytes:
        if self._seq > _MAX_SEQ:
            self._failed = True
            raise ValueError("message limit reached")
        return bytes(a ^ b for a, b in zip(self._base_nonce, _i2osp(self._seq, self._nn)))

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        self._usable()
        if not self._sender or self._aead_id == 0xFFFF:
            raise ValueError("seal unavailable")
        try:
            nonce = self._nonce()
            if self._aead_id == 1:
                out = AESGCM(self._key).encrypt(nonce, bytes(plaintext), bytes(aad))
            else:
                out = ChaCha20Poly1305(self._key).encrypt(nonce, bytes(plaintext), bytes(aad))
        except ValueError:
            raise
        except Exception:
            self._failed = True
            raise ValueError("encryption failed") from None
        self._seq += 1
        return out

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        self._usable()
        if self._sender or self._aead_id == 0xFFFF:
            raise ValueError("open unavailable")
        try:
            nonce = self._nonce()
            if self._aead_id == 1:
                out = AESGCM(self._key).decrypt(nonce, bytes(ciphertext), bytes(aad))
            else:
                out = ChaCha20Poly1305(self._key).decrypt(nonce, bytes(ciphertext), bytes(aad))
        except ValueError:
            raise
        except Exception:
            self._failed = True
            raise ValueError("authentication failed") from None
        self._seq += 1
        return out

    def export(self, exporter_context: bytes, length: int) -> bytes:
        self._usable()
        if not isinstance(exporter_context, bytes) or not isinstance(length, int) or length < 0 or length > 65535:
            raise ValueError("invalid exporter request")
        return _labeled_expand(self._exporter, b"sec", exporter_context, length, _suite_id(self._aead_id))


def setup_sender(mode: int, aead_id: int, pk_r: bytes, info: bytes = b"", *, sk_s: bytes | None = None,
                 psk: bytes | None = None, psk_id: bytes = b"", encap_rng: Callable[[int], bytes] | None = None):
    _validate(mode, aead_id, psk, psk_id, sk_s, None)
    pk_r_b = _check32(pk_r, "recipient key")
    if not isinstance(info, bytes):
        raise ValueError("invalid info")
    if mode in (2, 3) and sk_s is None:
        raise ValueError("sender key required")
    sk_e_raw = (encap_rng(32) if encap_rng else os.urandom(32))
    sk_e_raw = _check32(sk_e_raw, "ephemeral key")
    sk_e, pk_r_obj = _priv(sk_e_raw), _pub(pk_r_b)
    enc = _raw_public(sk_e)
    dh = _dh(sk_e, pk_r_obj)
    if mode in (2, 3):
        sk_s_obj = _priv(sk_s)
        dh += _dh(sk_s_obj, pk_r_obj)
        kem_ctx = enc + pk_r_b + _raw_public(sk_s_obj)
    else:
        kem_ctx = enc + pk_r_b
    shared = _labeled_extract(b"", b"eae_prk", dh, _KEM_SUITE_ID)
    shared = _labeled_expand(shared, b"shared_secret", kem_ctx, 32, _KEM_SUITE_ID)
    key, nonce, exp, nn = _key_schedule(mode, aead_id, shared, info, psk, psk_id)
    return enc, Context(key, nonce, exp, aead_id, True, nn)


def setup_receiver(mode: int, aead_id: int, enc: bytes, sk_r: bytes, info: bytes = b"", *, pk_s: bytes | None = None,
                   psk: bytes | None = None, psk_id: bytes = b""):
    _validate(mode, aead_id, psk, psk_id, None, pk_s)
    enc_b, sk_r_b = _check32(enc, "encapsulation"), _check32(sk_r, "recipient key")
    if not isinstance(info, bytes):
        raise ValueError("invalid info")
    if mode in (2, 3) and pk_s is None:
        raise ValueError("sender key required")
    sk_r_obj, enc_obj = _priv(sk_r_b), _pub(enc_b)
    dh = _dh(sk_r_obj, enc_obj)
    if mode in (2, 3):
        pk_s_b = _check32(pk_s, "sender key")
        dh += _dh(sk_r_obj, _pub(pk_s_b))
        kem_ctx = enc_b + _raw_public(sk_r_obj) + pk_s_b
    else:
        kem_ctx = enc_b + _raw_public(sk_r_obj)
    shared = _labeled_extract(b"", b"eae_prk", dh, _KEM_SUITE_ID)
    shared = _labeled_expand(shared, b"shared_secret", kem_ctx, 32, _KEM_SUITE_ID)
    key, nonce, exp, nn = _key_schedule(mode, aead_id, shared, info, psk, psk_id)
    return Context(key, nonce, exp, aead_id, False, nn)
