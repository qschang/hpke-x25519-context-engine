# HPKE X25519 context engine

Complete `/app/hpke_engine.py`. The module is used by a messaging service that needs
interoperable hybrid public-key encryption contexts. Implement the public API below;
callers will provide bytes and will not accept alternate encodings.

## Required profile

Implement the RFC 9180 profile `DHKEM(X25519, HKDF-SHA256)` with `HKDF-SHA256` as
the HPKE KDF. Support AEAD identifier `1` for AES-128-GCM and `3` for
ChaCha20-Poly1305. Also support AEAD identifier `0xffff`
as export-only: setup and `export()` work, while `seal()` and `open()` reject it.
The four HPKE modes are required: base (`0`), psk (`1`), auth (`2`), and auth_psk
(`3`). The implementation must follow RFC 9180 revision published by the RFC
Editor, including its labeled domain separation, X25519 encodings, key schedule,
and context construction. Use a maintained cryptographic library for primitives;
do not replace the HPKE API with a different protocol.

## Public API

Expose these callables and classes:

* `setup_sender(mode, aead_id, pk_r, info=b"", *, sk_s=None, psk=None,
  psk_id=b"", encap_rng=None) -> (enc, ctx)`
* `setup_receiver(mode, aead_id, enc, sk_r, info=b"", *, pk_s=None,
  psk=None, psk_id=b"") -> ctx`
* `class Context` with `seal(aad, plaintext)`, `open(aad, ciphertext)`,
  `export(exporter_context, length)`, and read-only `seq` and `aead_id` properties.
* `serialize_public_key(raw) -> bytes`, `deserialize_public_key(data) -> bytes`,
  `serialize_private_key(raw) -> bytes`, and `deserialize_private_key(data) -> bytes`.

`pk_r`, `pk_s`, `enc`, and all serialized X25519 keys are exactly 32-byte little-
endian byte strings. Private-key functions must accept exactly 32 bytes and return
exactly 32 bytes; they must reject malformed lengths rather than silently hashing or
truncating input. `encap_rng(n)` is optional and, when supplied, must be used for
the sender's 32-byte ephemeral private-key input; absent it, use an OS CSPRNG.

## Observable requirements

The sender and receiver contexts must interoperate for all four modes with both
message-protection AEADs; export-only setup and export must work in all four modes.
`seal` and `open` use the RFC sequence-number rule, preserve ordering, and
increment the sequence only after a successful operation. `open` must not advance
the sequence when authentication fails. Unsupported identifiers, wrong-role
operations, malformed keys, invalid mode/PSK combinations, exporter lengths outside
the RFC 9180 limit of 0 through 8,160 octets for HKDF-SHA256, and invalid
authentication must raise `ValueError` without exposing secret material. A context
that has encountered a fatal authentication error must remain unusable. Exporter
output must be deterministic for the same setup and must be independent of the AEAD
message sequence.

The implementation must generalize across valid inputs rather than special-case
particular keys, plaintexts, or parameter combinations. Do not return internal keys,
mutable aliases to key material, or plaintext from a failed `open`. The API is
single-threaded and one context is one sender or receiver; replay protection beyond
the ordered sequence state is not part of this interface.
