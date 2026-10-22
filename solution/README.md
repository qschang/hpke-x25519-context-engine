# Reference rationale

This solution is based on RFC 9180 and uses `cryptography` only for X25519 and AEAD
primitive operations. Protocol composition, labeled HKDF operations, context state,
and input checks are implemented in this package. The reference must pass all 14
independently scored behavior groups for reward 1.000.

## Independent domain challenges and test mapping

1. **C1_DHKEM_AND_LABELED_SCHEDULE — DHKEM transcript and labeled key schedule.**
   Suite identifiers, X25519 byte representation, context ordering, labeled
   extraction/expansion, and derived message material must match attributed RFC 9180
   values rather than merely agree between two endpoints. Covered by
   `T01-RFC-KEM-AEAD` and `T02-RFC-KEY-SCHEDULE`.
2. **C2_MODE_CREDENTIAL_BINDING — mode-specific credential binding.** Base, PSK,
   authenticated, and authenticated-PSK setup use different credential and context
   rules. Covered independently by `T03-BASE-INFO-BINDING`, `T04-PSK-MODE`,
   `T05-AUTH-MODE`, and `T06-AUTH-PSK-MODE`, including wrong-credential negatives.
3. **C3_AEAD_EXPORT_SEPARATION — AEAD-specific context and exporter semantics.**
   AES-128-GCM and ChaCha20-Poly1305 contexts must interoperate, while export-only
   setup must not create a message cipher. Export output is checked for peer
   agreement, the RFC HKDF-SHA256 length boundary, and independence from message
   sequence state. Covered by `T07-AES-GCM-CONTEXT`, `T08-CHACHA-CONTEXT`, and
   `T09-EXPORT-ONLY`.
4. **C4_SEQUENCE_AND_FAIL_CLOSED — ordered nonce state and authentication failure.**
   Successful operations advance state, failed authentication cannot consume a
   record, and a failed receiver remains unusable. `T10-SEQUENCE-ORDER` checks both
   RFC record ciphertexts (record 0 and record 1), preventing a shared wrong nonce
   rule from passing by endpoint agreement alone; `T11-FAIL-CLOSED` checks failure
   state and retry behavior.
5. **C5_INPUT_ROLE_AND_DH_BOUNDARIES — encoding, API role, and X25519 boundaries.**
   Raw-key serialization, suite/mode selection, PSK preconditions, wrong-role
   operations, associated-data authentication, and invalid/low-order DH inputs are
   checked by `T12-API-BOUNDARIES`, `T13-AAD-BINDING`, and `T14-LOW-ORDER-DH`.

## Scoring rationale

Weights sum exactly to 1.000. RFC-derived KEM and key-schedule behavior receive 0.25
because mistakes break interoperability while remaining self-consistent. Mode-specific
behavior receives 0.31 across the base, PSK, auth, and auth_psk cases. AEAD and
exporter correctness receive 0.20, including export-only semantics and the HKDF
output ceiling. Ordered state and fail-closed behavior receive 0.17 because nonce
misuse or post-authentication-failure use violates the context contract. API,
associated-data, and low-order input boundaries receive 0.07. A failed group loses
only its own weight; a partial repair cannot receive full score.

| Test ID | Weight | Contract covered |
|---|---:|---|
| `T01-RFC-KEM-AEAD` | 0.15 | RFC base encapsulation, ciphertext, and open |
| `T02-RFC-KEY-SCHEDULE` | 0.10 | RFC exporter values and setup-state independence |
| `T03-BASE-INFO-BINDING` | 0.07 | Base-mode transcript separation |
| `T04-PSK-MODE` | 0.08 | PSK mode and credential rejection |
| `T05-AUTH-MODE` | 0.08 | Auth mode and sender-key binding |
| `T06-AUTH-PSK-MODE` | 0.08 | Combined auth/PSK credential binding |
| `T07-AES-GCM-CONTEXT` | 0.06 | AES-GCM context interoperability |
| `T08-CHACHA-CONTEXT` | 0.06 | ChaCha20-Poly1305 context interoperability |
| `T09-EXPORT-ONLY` | 0.08 | Export-only modes, size boundary, message-state independence |
| `T10-SEQUENCE-ORDER` | 0.10 | RFC record 0/1 ciphertexts and sequence advancement |
| `T11-FAIL-CLOSED` | 0.07 | Authentication failure does not advance and disables context |
| `T12-API-BOUNDARIES` | 0.02 | Encoding, identifiers, credentials, and role API |
| `T13-AAD-BINDING` | 0.03 | Associated data is authenticated; mismatch is rejected |
| `T14-LOW-ORDER-DH` | 0.02 | X25519 low-order and encapsulation-input rejection |

Expected results use attributed RFC vectors where available and public contract
invariants otherwise. Synthetic key material and payloads are deterministic; no
production-data claim is made. These host-side checks do not substitute for an
environment build, positive and clean-start Harbor runs, model calibration, or human
domain/editorial review.
