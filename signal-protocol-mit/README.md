# signal-protocol-mit

**X3DH** and the **Double Ratchet** (the Signal protocol) for Node.js, written from Signal's public-domain
specifications, under the **MIT licence**. It offers the part of libsignal-node that [Baileys](https://github.com/WhiskeySockets/Baileys)
uses, so Baileys (WhatsApp Web) can run without GPL code. Where everything comes from: [PROVENANCE.md](PROVENANCE.md).

Copyright (c) 2026 Vicente Zaragoza Arnau. MIT, see [LICENSE](LICENSE).

> **Status:** interoperates with libsignal-node in tests (both directions) and through Baileys, including groups. Not yet
> used with real WhatsApp accounts for long periods: try it on a test number before relying on it.

## What it contains

| Export | What |
|---|---|
| `ProtocolAddress(name, deviceId)` | An address (`"34600111222.0"`) |
| `SessionBuilder(storage, address).initOutgoing(bundle)` | X3DH as initiator with the server's pre-key bundle |
| `SessionCipher(storage, address)` | `encrypt(data)` → `{ type: 3 \| 1, body }`, `decryptPreKeyWhisperMessage(data)`, `decryptWhisperMessage(data)` |
| `SessionRecord` | The sessions with one address; `serialize()` / `deserialize()` (its own JSON format) |
| `curve` (also `/src/curve.js`) | `generateKeyPair`, `calculateAgreement` (X25519), `calculateSignature` / `verifySignature` (XEdDSA) |
| `crypto` (also `/src/crypto.js`) | `encrypt` / `decrypt` (AES-256-CBC), `calculateMAC` (HMAC-SHA256), `deriveSecrets` (HKDF) |

Not included: sender keys for groups (Baileys has its own implementation, which calls `curve` and `crypto`), Sesame
(Baileys handles devices) and post-quantum PQXDH.

The storage object is the one Baileys passes: `loadSession`, `storeSession`, `isTrustedIdentity`, `loadPreKey`,
`removePreKey`, `loadSignedPreKey`, `getOurRegistrationId`, `getOurIdentity`.

## Using it with Baileys

Install it under the name Baileys imports (`libsignal`), for example with npm overrides:

```json
"overrides": { "libsignal": "npm:signal-protocol-mit@0.1.0" }
```

or by copying this package into `node_modules/libsignal`.

### Switching from libsignal

Session records written by libsignal-node are not read (that would require knowing its storage format): they read as
empty, and each session is built again with the next pre-key message. The account link (identity key, pre-keys) is kept.

## Tests

```
npm test
```

The interoperability tests run against libsignal-node as a black box when it is installed (`LIBSIGNAL_ORACLE=<path to
node_modules/libsignal>`); otherwise they are skipped.
