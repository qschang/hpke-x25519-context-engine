"""Public starter interface for the HPKE context-engine task."""
from __future__ import annotations

from typing import Callable


class Context:
    @property
    def seq(self) -> int:
        raise NotImplementedError

    @property
    def aead_id(self) -> int:
        raise NotImplementedError

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        raise NotImplementedError

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        raise NotImplementedError

    def export(self, exporter_context: bytes, length: int) -> bytes:
        raise NotImplementedError


def setup_sender(mode: int, aead_id: int, pk_r: bytes, info: bytes = b"", *,
                 sk_s: bytes | None = None, psk: bytes | None = None,
                 psk_id: bytes = b"", encap_rng: Callable[[int], bytes] | None = None):
    raise NotImplementedError


def setup_receiver(mode: int, aead_id: int, enc: bytes, sk_r: bytes, info: bytes = b"", *,
                   pk_s: bytes | None = None, psk: bytes | None = None,
                   psk_id: bytes = b""):
    raise NotImplementedError


def serialize_public_key(raw: bytes) -> bytes:
    raise NotImplementedError


def deserialize_public_key(data: bytes) -> bytes:
    raise NotImplementedError


def serialize_private_key(raw: bytes) -> bytes:
    raise NotImplementedError


def deserialize_private_key(data: bytes) -> bytes:
    raise NotImplementedError
