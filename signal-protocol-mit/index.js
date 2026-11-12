// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Vicente Zaragoza Arnau
//
// X3DH and the Double Ratchet for Node.js, written from Signal's public-domain specifications (PROVENANCE.md). The
// exports are the subset of libsignal-node that Baileys uses, so it can take its place (README).

import * as curve from './src/curve.js';
import * as crypto from './src/crypto.js';

export { ProtocolAddress, SessionRecord, SessionBuilder, SessionCipher } from './src/session.js';
export { curve, crypto };
