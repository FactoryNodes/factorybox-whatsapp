// Copyright (c) 2026 Vicente Zaragoza Arnau. MIT licence (see LICENSE).
//
// The wire messages under the names libsignal-node gives them. Baileys 7 imports this file
// (`libsignal/src/protobufs.js`) to read the identity key of a pre-key message before decrypting it
// (`PreKeyWhisperMessage.decode(ciphertext.slice(1)).identityKey`), to notice when a contact's identity changes.
// The messages themselves are the ones in protobuf.js (from the Signal specifications, PROVENANCE.md).

export { SignalMessage as WhisperMessage, PreKeySignalMessage as PreKeyWhisperMessage } from './protobuf.js';
