// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Vicente Zaragoza Arnau
//
// Symmetric primitives. The choices are the ones recommended by "The Double Ratchet Algorithm" (Signal, rev. 1,
// 2016-11-20, public domain), section 5.2 "Recommended cryptographic algorithms": HKDF with SHA-256 (RFC 5869),
// HMAC-SHA256 and AES-256 in CBC mode with PKCS#7 padding. Everything comes from Node's built-in crypto module.

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, createHash, timingSafeEqual } from 'node:crypto';

const toBuffer = (data) => (Buffer.isBuffer(data) ? data : Buffer.from(data));

/** AES-256-CBC with PKCS#7 padding. Argument order (key, data, iv) is the one Baileys calls. */
export function encrypt(key, data, iv) {
    const cipher = createCipheriv('aes-256-cbc', toBuffer(key), toBuffer(iv));
    return Buffer.concat([cipher.update(toBuffer(data)), cipher.final()]);
}

/** AES-256-CBC with PKCS#7 padding (throws if the padding is wrong). */
export function decrypt(key, data, iv) {
    const decipher = createDecipheriv('aes-256-cbc', toBuffer(key), toBuffer(iv));
    return Buffer.concat([decipher.update(toBuffer(data)), decipher.final()]);
}

/** HMAC-SHA256 (32 bytes). */
export function calculateMAC(key, data) {
    return createHmac('sha256', toBuffer(key)).update(toBuffer(data)).digest();
}

/** SHA-512. */
export function hash(data) {
    return createHash('sha512').update(toBuffer(data)).digest();
}

/**
 * HKDF-SHA256 (RFC 5869, extract then expand) returning `chunks` blocks of 32 bytes. The Double Ratchet derives its root
 * and chain keys (and the message keys) this way; Baileys' group cipher calls it with three arguments.
 */
export function deriveSecrets(input, salt, info, chunks = 3) {
    if (chunks < 1 || chunks > 3) throw new Error('deriveSecrets: 1 to 3 chunks of 32 bytes');
    const okm = Buffer.from(hkdfSync('sha256', toBuffer(input), toBuffer(salt), toBuffer(info), 32 * chunks));
    return Array.from({ length: chunks }, (_, i) => okm.subarray(32 * i, 32 * (i + 1)));
}

/** Constant-time comparison of two MACs (truncated or not). */
export function verifyMAC(data, key, mac, length) {
    const expected = calculateMAC(key, data).subarray(0, length);
    if (expected.length !== mac.length || !timingSafeEqual(expected, Buffer.from(mac))) throw new Error('Bad MAC');
}

export function getRandomBytes(length) {
    return randomBytes(length);
}
