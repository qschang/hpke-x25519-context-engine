from __future__ import annotations

import hashlib
import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import hpke_engine as h


def key(label: str) -> tuple[bytes, bytes]:
    raw = hashlib.sha256(("hpke-e3/" + label).encode()).digest()
    sk = X25519PrivateKey.from_private_bytes(raw)
    return raw, sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def expect_value_error(fn) -> None:
    try:
        fn()
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def rfc_base():
    sk_e = bytes.fromhex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
    sk_r = bytes.fromhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
    pk_r = bytes.fromhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
    info = bytes.fromhex("4f6465206f6e2061204772656369616e2055726e")
    return sk_e, sk_r, pk_r, info


def test_rfc_base_kem_and_ciphertext() -> None:
    """T01: the public RFC profile must match the independent base-mode vector."""
    sk_e, sk_r, pk_r, info = rfc_base()
    enc, sender = h.setup_sender(0, 1, pk_r, info, encap_rng=lambda n: sk_e)
    assert enc.hex() == "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
    pt = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
    aad = b"Count-0"
    expected = bytes.fromhex(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
        "6d8770ac83d07bea87e13c512a"
    )
    ciphertext = sender.seal(aad, pt)
    assert ciphertext == expected
    receiver = h.setup_receiver(0, 1, enc, sk_r, info)
    assert receiver.open(aad, ciphertext) == pt


def test_rfc_base_key_schedule_exports() -> None:
    """T02: exporter values and initial sequence state must follow the public profile."""
    sk_e, _, pk_r, info = rfc_base()
    _, sender = h.setup_sender(0, 1, pk_r, info, encap_rng=lambda n: sk_e)
    expected = {
        b"": "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
        b"\x00": "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
        b"TestContext": "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931",
    }
    for context, value in expected.items():
        assert sender.export(context, 32).hex() == value
    assert sender.seq == 0


def test_base_mode_context_matrix() -> None:
    """T03: changing public context information must separate base-mode transcripts."""
    sk_r, pk_r = key("recipient-base")
    seen = []

    def rng(n: int) -> bytes:
        seen.append(n)
        return hashlib.sha256(b"ephemeral-base").digest()

    enc_a, sender_a = h.setup_sender(0, 1, pk_r, b"service-A", encap_rng=rng)
    enc_b, sender_b = h.setup_sender(0, 1, pk_r, b"service-B", encap_rng=rng)
    assert seen == [32, 32]
    assert enc_a == enc_b
    receiver_a = h.setup_receiver(0, 1, enc_a, sk_r, b"service-A")
    receiver_b = h.setup_receiver(0, 1, enc_b, sk_r, b"service-B")
    ct_a = sender_a.seal(b"header", b"payload")
    ct_b = sender_b.seal(b"header", b"payload")
    assert ct_a != ct_b
    assert receiver_a.open(b"header", ct_a) == b"payload"
    expect_value_error(lambda: receiver_a.open(b"header", ct_b))
    assert receiver_b.open(b"header", ct_b) == b"payload"


def test_psk_mode() -> None:
    """T04: PSK mode must bind both credentials and reject an incomplete identifier."""
    sk_r, pk_r = key("recipient-psk")
    psk, psk_id = b"psk-for-device-42", b"device-42"
    for aead_id in (1, 3):
        enc, sender = h.setup_sender(1, aead_id, pk_r, b"psk-info", psk=psk, psk_id=psk_id,
                                     encap_rng=lambda n: hashlib.sha256(b"psk-e" + bytes([aead_id])).digest())
        receiver = h.setup_receiver(1, aead_id, enc, sk_r, b"psk-info", psk=psk, psk_id=psk_id)
        ct = sender.seal(b"aad", b"psk message")
        assert receiver.open(b"aad", ct) == b"psk message"
        wrong_psk = h.setup_receiver(1, aead_id, enc, sk_r, b"psk-info", psk=b"wrong", psk_id=psk_id)
        expect_value_error(lambda wrong_psk=wrong_psk, ct=ct: wrong_psk.open(b"aad", ct))
    expect_value_error(lambda: h.setup_sender(1, 1, pk_r, b"psk-info", psk=psk, psk_id=b""))


def test_auth_mode() -> None:
    """T05: authenticated mode must bind the sender key and require it at setup."""
    sk_r, pk_r = key("recipient-auth")
    sk_s, pk_s = key("sender-auth")
    _, wrong_pk_s = key("wrong-sender-auth")
    for aead_id in (1, 3):
        enc, sender = h.setup_sender(2, aead_id, pk_r, b"auth-info", sk_s=sk_s,
                                     encap_rng=lambda n: hashlib.sha256(b"auth-e" + bytes([aead_id])).digest())
        receiver = h.setup_receiver(2, aead_id, enc, sk_r, b"auth-info", pk_s=pk_s)
        ct = sender.seal(b"aad", b"authenticated")
        assert receiver.open(b"aad", ct) == b"authenticated"
        wrong_receiver = h.setup_receiver(2, aead_id, enc, sk_r, b"auth-info", pk_s=wrong_pk_s)
        expect_value_error(lambda wrong_receiver=wrong_receiver, ct=ct: wrong_receiver.open(b"aad", ct))
    expect_value_error(lambda: h.setup_sender(2, 1, pk_r, b"auth-info"))
    expect_value_error(lambda: h.setup_receiver(2, 1, enc, sk_r, b"auth-info"))


def test_auth_psk_mode() -> None:
    """T06: authenticated-PSK mode must bind sender and PSK credentials together."""
    sk_r, pk_r = key("recipient-auth-psk")
    sk_s, pk_s = key("sender-auth-psk")
    psk, psk_id = b"auth-psk-secret", b"tenant-9"
    for aead_id in (1, 3):
        enc, sender = h.setup_sender(3, aead_id, pk_r, b"auth-psk-info", sk_s=sk_s,
                                     psk=psk, psk_id=psk_id,
                                     encap_rng=lambda n: hashlib.sha256(b"auth-psk-e" + bytes([aead_id])).digest())
        receiver = h.setup_receiver(3, aead_id, enc, sk_r, b"auth-psk-info", pk_s=pk_s,
                                     psk=psk, psk_id=psk_id)
        ct = sender.seal(b"aad", b"authenticated psk")
        assert receiver.open(b"aad", ct) == b"authenticated psk"
        wrong = h.setup_receiver(3, aead_id, enc, sk_r, b"auth-psk-info", pk_s=pk_s,
                                 psk=psk, psk_id=b"other-tenant")
        expect_value_error(lambda wrong=wrong, ct=ct: wrong.open(b"aad", ct))


def test_aes_gcm_context() -> None:
    """T07: AES-128-GCM contexts must interoperate while advancing ordered state."""
    sk_r, pk_r = key("recipient-aes")
    enc, sender = h.setup_sender(0, 1, pk_r, b"aes", encap_rng=lambda n: b"\x17" * 32)
    receiver = h.setup_receiver(0, 1, enc, sk_r, b"aes")
    for i in range(4):
        aad, pt = f"aes-aad-{i}".encode(), hashlib.sha256(bytes([i])).digest()
        ct = sender.seal(aad, pt)
        assert receiver.open(aad, ct) == pt
    assert sender.seq == receiver.seq == 4


def test_chacha20_poly1305_context() -> None:
    """T08: ChaCha20-Poly1305 contexts must interoperate across multiple records."""
    sk_r, pk_r = key("recipient-chacha")
    enc, sender = h.setup_sender(0, 3, pk_r, b"chacha", encap_rng=lambda n: b"\x29" * 32)
    receiver = h.setup_receiver(0, 3, enc, sk_r, b"chacha")
    for i in range(4):
        aad = f"chacha-aad-{i}".encode()
        pt = hashlib.sha256(bytes([i])).digest()[:23 + i]
        ct = sender.seal(aad, pt)
        assert receiver.open(aad, ct) == pt
    assert sender.seq == receiver.seq == 4


def test_export_only_and_export_limits() -> None:
    """T09: export-only contexts and the HKDF-SHA256 exporter length boundary are enforced."""
    sk_r, pk_r = key("recipient-export")
    enc, sender = h.setup_sender(0, 0xFFFF, pk_r, b"export", encap_rng=lambda n: b"\x31" * 32)
    receiver = h.setup_receiver(0, 0xFFFF, enc, sk_r, b"export")
    assert sender.export(b"ctx", 0) == b""
    assert sender.export(b"ctx", 8160) == receiver.export(b"ctx", 8160)
    assert sender.seq == receiver.seq == 0
    expect_value_error(lambda: sender.seal(b"", b"x"))
    expect_value_error(lambda: receiver.open(b"", b"x"))
    expect_value_error(lambda: sender.export(b"ctx", 8161))

    sk_s, pk_s = key("sender-export")
    modes = [
        (0, {}),
        (1, {"psk": b"export-psk", "psk_id": b"export-id"}),
        (2, {"sk_s": sk_s}),
        (3, {"sk_s": sk_s, "psk": b"export-psk", "psk_id": b"export-id"}),
    ]
    for mode, credentials in modes:
        enc_m, sender_m = h.setup_sender(
            mode, 0xFFFF, pk_r, b"export-modes", encap_rng=lambda n: b"\x33" * 32,
            **credentials,
        )
        receiver_credentials = dict(credentials)
        receiver_credentials.pop("sk_s", None)
        if mode in (2, 3):
            receiver_credentials["pk_s"] = pk_s
        receiver_m = h.setup_receiver(
            mode, 0xFFFF, enc_m, sk_r, b"export-modes", **receiver_credentials
        )
        assert sender_m.export(b"mode", 32) == receiver_m.export(b"mode", 32)
        expect_value_error(lambda sender_m=sender_m: sender_m.seal(b"", b"x"))
        expect_value_error(lambda receiver_m=receiver_m: receiver_m.open(b"", b"x"))

    live_enc, live_sender = h.setup_sender(
        0, 1, pk_r, b"export-sequence", encap_rng=lambda n: b"\x32" * 32
    )
    live_receiver = h.setup_receiver(0, 1, live_enc, sk_r, b"export-sequence")
    before = live_sender.export(b"stable-context", 48)
    first = live_sender.seal(b"aad", b"message")
    assert live_receiver.open(b"aad", first) == b"message"
    second = live_sender.seal(b"aad", b"next")
    assert live_receiver.open(b"aad", second) == b"next"
    assert live_sender.export(b"stable-context", 48) == before
    assert live_receiver.export(b"stable-context", 48) == before


def test_nonce_sequence_and_order() -> None:
    """T10: record nonces and sequence advancement must preserve the RFC order."""
    sk_e, sk_r, pk_r, info = rfc_base()
    enc_vector, sender_vector = h.setup_sender(0, 1, pk_r, info, encap_rng=lambda n: sk_e)
    vector_pt = bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479")
    vector_ct0 = bytes.fromhex(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9"
        "6d8770ac83d07bea87e13c512a"
    )
    vector_ct1 = bytes.fromhex(
        "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc85354"
        "58c2494e8a6eab251c03d0c22a56b8ca42c2063b84"
    )
    assert sender_vector.seal(b"Count-0", vector_pt) == vector_ct0
    assert sender_vector.seal(b"Count-1", vector_pt) == vector_ct1
    receiver_vector = h.setup_receiver(0, 1, enc_vector, sk_r, info)
    assert receiver_vector.open(b"Count-0", vector_ct0) == vector_pt
    assert receiver_vector.open(b"Count-1", vector_ct1) == vector_pt
    assert sender_vector.seq == receiver_vector.seq == 2

    sk_r, pk_r = key("recipient-sequence")
    enc, sender = h.setup_sender(0, 1, pk_r, b"sequence", encap_rng=lambda n: b"\x42" * 32)
    receiver = h.setup_receiver(0, 1, enc, sk_r, b"sequence")
    ciphertexts = [sender.seal(b"same-aad", b"same-plaintext") for _ in range(3)]
    assert len(set(ciphertexts)) == 3
    assert sender.seq == 3 and receiver.seq == 0
    for expected, ciphertext in enumerate(ciphertexts):
        assert receiver.open(b"same-aad", ciphertext) == b"same-plaintext"
        assert receiver.seq == expected + 1
    expect_value_error(lambda: receiver.open(b"same-aad", ciphertexts[0]))


def test_authentication_failure_is_fatal() -> None:
    """T11: authentication failure must preserve sequence state and make the context unusable."""
    sk_r, pk_r = key("recipient-failure")
    enc, sender = h.setup_sender(0, 3, pk_r, b"failure", encap_rng=lambda n: b"\x53" * 32)
    receiver = h.setup_receiver(0, 3, enc, sk_r, b"failure")
    ct = sender.seal(b"aad", b"secret")
    tampered = ct[:-1] + bytes([ct[-1] ^ 1])
    expect_value_error(lambda: receiver.open(b"aad", tampered))
    assert receiver.seq == 0
    expect_value_error(lambda: receiver.open(b"aad", ct))
    expect_value_error(lambda: receiver.export(b"", 1))


def test_input_role_and_serialization_boundaries() -> None:
    """T12: public encodings, identifiers, credentials, and sender/receiver roles are validated."""
    sk_r, pk_r = key("recipient-boundary")
    sample = bytes(range(32))
    assert h.serialize_public_key(sample) == sample
    assert h.deserialize_public_key(sample) == sample
    assert h.serialize_private_key(sample) == sample
    assert h.deserialize_private_key(sample) == sample
    for fn in (h.serialize_public_key, h.deserialize_public_key,
               h.serialize_private_key, h.deserialize_private_key):
        for bad in (b"", b"x" * 31, b"x" * 33, "not-bytes"):
            expect_value_error(lambda fn=fn, bad=bad: fn(bad))
    for mode in (-1, 4, 99):
        expect_value_error(lambda mode=mode: h.setup_sender(mode, 1, pk_r))
    for aead in (0, 2, 4, 0x10000):
        expect_value_error(lambda aead=aead: h.setup_sender(0, aead, pk_r))
    for bad_key in (b"", b"x" * 31, b"x" * 33, "not-bytes"):
        expect_value_error(lambda bad_key=bad_key: h.setup_sender(0, 1, bad_key))
        expect_value_error(lambda bad_key=bad_key: h.setup_receiver(0, 1, b"e" * 32, bad_key))
        expect_value_error(lambda bad_key=bad_key: h.setup_receiver(0, 1, bad_key, sk_r))
    expect_value_error(lambda: h.setup_sender(1, 1, pk_r))
    expect_value_error(lambda: h.setup_sender(0, 1, pk_r, psk=b"psk", psk_id=b"id"))
    enc, sender = h.setup_sender(0, 1, pk_r, encap_rng=lambda n: b"\x64" * 32)
    receiver = h.setup_receiver(0, 1, enc, sk_r)
    expect_value_error(lambda: sender.open(b"", b""))
    expect_value_error(lambda: receiver.seal(b"", b""))
    expect_value_error(lambda: sender.export(b"", -1))
    for attribute in ("seq", "aead_id"):
        try:
            setattr(sender, attribute, 99)
        except (AttributeError, TypeError):
            pass
        else:
            raise AssertionError(f"{attribute} must be read-only")


def test_associated_data_binding() -> None:
    """T13: associated data is authenticated and a changed header is rejected."""
    sk_r, pk_r = key("recipient-binding")
    enc, sender = h.setup_sender(0, 1, pk_r, b"aad-binding", encap_rng=lambda n: b"\x75" * 32)
    ct = sender.seal(b"header-A", b"authenticated record")
    wrong_aad_receiver = h.setup_receiver(0, 1, enc, sk_r, b"aad-binding")
    expect_value_error(lambda: wrong_aad_receiver.open(b"header-B", ct))
    assert wrong_aad_receiver.seq == 0
    correct_receiver = h.setup_receiver(0, 1, enc, sk_r, b"aad-binding")
    assert correct_receiver.open(b"header-A", ct) == b"authenticated record"


def test_low_order_dh_and_rng_contract() -> None:
    """T14: low-order DH inputs and malformed encapsulation randomness are rejected."""
    sk_r, pk_r = key("recipient-low-order")
    rejected_low_order = False
    try:
        h.setup_sender(0, 1, b"\x00" * 32, encap_rng=lambda n: b"\x81" * 32)
    except ValueError:
        rejected_low_order = True
    assert rejected_low_order
    expect_value_error(lambda: h.setup_sender(0, 1, pk_r, encap_rng=lambda n: b"short"))
    expect_value_error(lambda: h.setup_receiver(0, 1, b"\x00" * 32, sk_r))


GROUPS = [
    ("T01-RFC-KEM-AEAD", test_rfc_base_kem_and_ciphertext, 0.15),
    ("T02-RFC-KEY-SCHEDULE", test_rfc_base_key_schedule_exports, 0.10),
    ("T03-BASE-INFO-BINDING", test_base_mode_context_matrix, 0.07),
    ("T04-PSK-MODE", test_psk_mode, 0.08),
    ("T05-AUTH-MODE", test_auth_mode, 0.08),
    ("T06-AUTH-PSK-MODE", test_auth_psk_mode, 0.08),
    ("T07-AES-GCM-CONTEXT", test_aes_gcm_context, 0.06),
    ("T08-CHACHA-CONTEXT", test_chacha20_poly1305_context, 0.06),
    ("T09-EXPORT-ONLY", test_export_only_and_export_limits, 0.08),
    ("T10-SEQUENCE-ORDER", test_nonce_sequence_and_order, 0.10),
    ("T11-FAIL-CLOSED", test_authentication_failure_is_fatal, 0.07),
    ("T12-API-BOUNDARIES", test_input_role_and_serialization_boundaries, 0.02),
    ("T13-AAD-BINDING", test_associated_data_binding, 0.03),
    ("T14-LOW-ORDER-DH", test_low_order_dh_and_rng_contract, 0.02),
]
