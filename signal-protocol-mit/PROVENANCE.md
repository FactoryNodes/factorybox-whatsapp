# Provenance

Where every part of this library comes from. It was written from **Signal's specifications**, which Signal released into
the public domain, and from **WhatsApp's protocol schema** as published with Baileys (MIT). The source code of
libsignal-node, libsignal-protocol-java/javascript and libsignal (Rust) — all GPL or AGPL — was **not read or copied**
while writing it. The original libsignal-node was only *run* as a black box in the interoperability tests (inputs in,
outputs compared), as the EU Software Directive (2009/24/EC, art. 6) allows to achieve interoperability.

Written on 2026-10-15 by Claude (Anthropic) for Vicente Zaragoza Arnau, who owns it. A note on that: a language model is
trained on public code, which may include libsignal; the code below was derived from the specifications, step by step,
and is reviewed against them, but no tool can certify that a model has never seen a given program.

## Specifications (public domain)

| Document | Revision | Used for |
|---|---|---|
| [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/) | 1, 2016-11-04 | `SessionBuilder.initOutgoing`, `SessionCipher.respondX3DH`: DH1…DH4 (3.3), F = 32 × 0xFF prefix and HKDF with zero salt (2.2), signed pre-key verification and one-time pre-key deletion (3.3), associated data AD = IKA ‖ IKB (3.3) |
| [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) | 1, 2016-11-20 | `session.js`: RatchetInitAlice / RatchetInitBob (3.3), RatchetEncrypt / RatchetDecrypt, DHRatchet, TrySkippedMessageKeys / SkipMessageKeys and MAX_SKIP (3.4, 3.5), KDF_RK and KDF_CK with HMAC constants 0x01 / 0x02 (5.2), ENCRYPT with HKDF 80 bytes → AES-256-CBC key, HMAC key and IV (5.2) |
| [The XEdDSA and VXEdDSA Signature Schemes](https://signal.org/docs/specifications/xeddsa/) | 1, 2016-10-20 | `curve.js`: calculate_key_pair (2.3), hash_i (2.5), u-to-Edwards conversion (2.2), xeddsa_sign / xeddsa_verify (3) |
| RFC 7748 (X25519), RFC 5869 (HKDF), FIPS 180-4 (SHA-256/512), FIPS 197 + SP 800-38A (AES-CBC), RFC 2104 (HMAC) | — | Primitives, from Node.js `crypto` and @noble/curves |

## Values the specifications leave to the application (WhatsApp's)

The specifications say these are "application-specific". These are the values WhatsApp uses; they are facts needed for
interoperability, not code. Each one is checked by the black-box interoperability tests (a wrong value makes every
message fail).

| Value | Where it is publicly documented |
|---|---|
| Wire format: `SignalMessage { ratchetKey=1, counter=2, previousCounter=3, ciphertext=4 }`, `PreKeySignalMessage { preKeyId=1, baseKey=2, identityKey=3, message=4, registrationId=5, signedPreKeyId=6 }` | `WAProto.proto` in Baileys (MIT) |
| Version byte 0x33 before each message, HMAC truncated to 8 bytes and appended, HMAC over sender identity ‖ receiver identity ‖ message | WhatsApp Encryption Overview (security whitepaper); widely described in public analyses of the protocol |
| HKDF info strings "WhisperText" (X3DH), "WhisperRatchet" (KDF_RK), "WhisperMessageKeys" (message keys); "WhisperGroup" is used by Baileys' own group code | Same; "WhisperGroup" is visible in Baileys (MIT) |
| X3DH output of 64 bytes (root key ‖ chain key), public keys with a 0x05 type byte | WhatsApp Encryption Overview ("Root Key and Chain Key"); the 0x05 byte is visible in Baileys (`KEY_BUNDLE_TYPE`) |
| Legacy Curve25519 signatures with the Edwards sign bit in the top bit of the last byte (accepted when verifying) | Public discussion of pre-XEdDSA Curve25519 signatures; accepted only for compatibility |
| The functions, arguments and storage interface Baileys calls (`SessionCipher.encrypt` → `{ type: 3 | 1, body }`, `crypto.deriveSecrets`, `curve.verifySignature` throwing on failure…) | Baileys' source (MIT): `lib/Signal/libsignal.js`, `lib/Utils/crypto.js`, `lib/Signal/Group/*` |

## Dependencies

| Package | Licence | Use |
|---|---|---|
| [@noble/curves](https://github.com/paulmillr/noble-curves) 1.9.7 (with @noble/hashes) | MIT | Edwards25519 and X25519 arithmetic (audited) |
| Node.js `crypto` | MIT | AES-CBC, HMAC, HKDF, SHA-512, random bytes |

## Tests

- `test/crypto.test.js`: RFC 5869 test case 1; round trips; same results as the black box.
- `test/curve.test.js`: XEdDSA sign / verify / reject; X25519; signatures and agreements against the black box, both ways.
- `test/session.test.js`: whole conversations (pre-key messages, answers, several ratchet steps, messages out of order,
  late messages, tampered and repeated messages) ours ↔ ours and **ours ↔ black box in both directions**, with and
  without a one-time pre-key.
- Outside this package (FactoryNodes): the same flows through Baileys' own `makeLibSignalRepository`, including group
  messages, give the same results with this library as with libsignal-node.

The black-box tests run only where libsignal-node is installed (`LIBSIGNAL_ORACLE` or the FactoryNodes build cache);
elsewhere they are skipped.
