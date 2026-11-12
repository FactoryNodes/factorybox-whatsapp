// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Vicente Zaragoza Arnau
//
// Curve25519: key agreement (X25519, RFC 7748) and signatures with Montgomery keys (XEdDSA, "The XEdDSA and VXEdDSA
// Signature Schemes", Signal, rev. 1, 2016-10-20, public domain). The group arithmetic comes from @noble/curves (MIT).
//
// Key formats (the ones Baileys uses): a private key is 32 bytes; a public key is 33 bytes, a type byte 0x05 followed
// by the 32-byte Montgomery u-coordinate. 32-byte public keys are accepted too.

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { hash } from './crypto.js';
import { randomBytes } from 'node:crypto';

export const KEY_TYPE = 0x05;

const Point = ed25519.ExtendedPoint;
const p = ed25519.CURVE.Fp.ORDER;   // 2^255 - 19
const q = ed25519.CURVE.n;          // order of the base point

const mod = (a, m) => ((a % m) + m) % m;

function bytesToNumberLE(bytes) {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    return n;
}

function numberToBytesLE(n, length = 32) {
    const out = Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    return out;
}

function invert(a, m) {
    // Fermat: a^(m-2) mod m (m prime)
    let result = 1n, base = mod(a, m), e = m - 2n;
    while (e > 0n) {
        if (e & 1n) result = (result * base) % m;
        base = (base * base) % m;
        e >>= 1n;
    }
    return result;
}

/** The 32-byte u-coordinate of a public key given with or without its 0x05 type byte. */
export function rawPublic(pubKey) {
    const key = Buffer.from(pubKey);
    if (key.length === 33) {
        if (key[0] !== KEY_TYPE) throw new Error('Invalid public key type');
        return key.subarray(1);
    }
    if (key.length === 32) return key;
    throw new Error('Invalid public key length');
}

/** X25519 private-key clamping (RFC 7748, section 5). */
function clamp(privKey) {
    const k = Buffer.from(privKey);
    if (k.length !== 32) throw new Error('Invalid private key length');
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return k;
}

/** A new key pair: { pubKey: 33 bytes (0x05 + u), privKey: 32 bytes, clamped }. */
export function generateKeyPair() {
    const privKey = clamp(randomBytes(32));
    return { pubKey: Buffer.concat([Buffer.from([KEY_TYPE]), Buffer.from(x25519.getPublicKey(privKey))]), privKey };
}

/** X25519 shared secret (32 bytes) between our private key and their public key. */
export function calculateAgreement(pubKey, privKey) {
    return Buffer.from(x25519.getSharedSecret(clamp(privKey), rawPublic(pubKey)));
}

// ---------- XEdDSA (sections 2.3, 2.5 and 3 of the XEdDSA specification) ----------

/** hash_i(X) = hash(2^b - 1 - i || X), b = 256 (spec 2.5): the prefix is 32 little-endian bytes. */
function hashI(i, ...parts) {
    const prefix = Buffer.alloc(32, 0xff);
    prefix[0] = 0xff - i;
    return hash(Buffer.concat([prefix, ...parts.map((x) => Buffer.from(x))]));
}

/** calculate_key_pair(k) (spec 2.3): the Edwards public key A with sign bit 0, and the private scalar a that gives it. */
function calculateKeyPair(privKey) {
    const k = mod(bytesToNumberLE(clamp(privKey)), q);
    const E = Point.BASE.multiply(k);
    const encoded = Buffer.from(E.toRawBytes());
    const signBit = encoded[31] & 0x80;
    const a = signBit ? mod(-k, q) : k;
    encoded[31] &= 0x7f;   // A.s = 0
    return { A: encoded, a };
}

/** xeddsa_sign(k, M, Z) (spec 3): a 64-byte signature R || s. */
export function calculateSignature(privKey, message, random = randomBytes(64)) {
    const { A, a } = calculateKeyPair(privKey);
    const r = mod(bytesToNumberLE(hashI(1, numberToBytesLE(a), message, random)), q);
    if (r === 0n) return calculateSignature(privKey, message);   // probability 2^-252: another Z
    const R = Buffer.from(Point.BASE.multiply(r).toRawBytes());
    const h = mod(bytesToNumberLE(hash(Buffer.concat([R, A, Buffer.from(message)]))), q);
    const s = mod(r + h * a, q);
    return Buffer.concat([R, numberToBytesLE(s)]);
}

/** convert_mont(u) (spec 2.2): the Edwards y of the Montgomery u, sign bit `sign`. */
function montgomeryToEdwards(u, sign) {
    const y = mod((u - 1n) * invert(u + 1n, p), p);
    const bytes = numberToBytesLE(y);
    bytes[31] = (bytes[31] & 0x7f) | sign;
    return bytes;
}

/**
 * Note on timing: the secret scalars are handled with JavaScript BigInt, which is not constant-time; the multiplications
 * by secrets use @noble/curves' constant-time path. The same holds for any BigInt-based implementation.
 */

/**
 * xeddsa_verify(u, M, (R || s)) (spec 3). Throws if the signature is not valid and returns true if it is (Baileys checks
 * both: its group cipher reads the result, its key helper catches the error).
 *
 * Interoperability note: signatures made before XEdDSA (Curve25519 signatures that carried the Edwards sign bit of A in
 * the top bit of the last byte) are also accepted: with that bit set, it is taken as the sign of A and cleared from s.
 */
export function verifySignature(pubKey, message, signature) {
    if (!verify(pubKey, message, signature)) throw new Error('Invalid signature');
    return true;
}

function verify(pubKey, message, signature) {
    const sig = Buffer.from(signature);
    if (sig.length !== 64) return false;
    const u = bytesToNumberLE(rawPublic(pubKey));
    if (u >= p) return false;
    const R = sig.subarray(0, 32);
    const sBytes = Buffer.from(sig.subarray(32));
    const sign = sBytes[31] & 0x80;
    sBytes[31] &= 0x7f;
    const s = bytesToNumberLE(sBytes);
    if (s >= q) return false;   // the spec requires s < 2^|q|; here the stricter canonical s < q
    let A, Rpoint;
    try {
        A = Point.fromHex(montgomeryToEdwards(u, sign));   // on_curve(A)
        Rpoint = Point.fromHex(R);
    } catch {
        return false;
    }

    const h = mod(bytesToNumberLE(hash(Buffer.concat([R, A.toRawBytes(), Buffer.from(message)]))), q);
    // Public data only: the variable-time multiplication is fine here
    const check = Point.BASE.multiplyUnsafe(s).subtract(A.multiplyUnsafe(h));
    return check.equals(Rpoint);
}
