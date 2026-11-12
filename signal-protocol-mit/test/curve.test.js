import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as curve from '../src/curve.js';
import { oracle } from './_oracle.js';

test('XEdDSA: sign, verify and reject a tampered message', () => {
    const { pubKey, privKey } = curve.generateKeyPair();
    assert.equal(pubKey.length, 33);
    assert.equal(pubKey[0], 5);
    const msg = Buffer.from('mensaje');
    const sig = curve.calculateSignature(privKey, msg);
    assert.equal(sig.length, 64);
    assert.equal(curve.verifySignature(pubKey, msg, sig), true);
    assert.equal(curve.verifySignature(pubKey.subarray(1), msg, sig), true);   // 32-byte public key
    assert.throws(() => curve.verifySignature(pubKey, Buffer.from('mensajf'), sig));
    const bad = Buffer.from(sig); bad[5] ^= 1;
    assert.throws(() => curve.verifySignature(pubKey, msg, bad));
});

test('X25519 agreement is symmetric', () => {
    const a = curve.generateKeyPair(), b = curve.generateKeyPair();
    assert.deepEqual(curve.calculateAgreement(b.pubKey, a.privKey), curve.calculateAgreement(a.pubKey, b.privKey));
});

test('interop with the black box: signatures and agreements both ways', { skip: !oracle && 'no oracle' }, () => {
    for (let i = 0; i < 20; i++) {
        const ours = curve.generateKeyPair(), theirs = oracle.curve.generateKeyPair();
        const msg = Buffer.from(`m${i}`);
        assert.equal(curve.verifySignature(theirs.pubKey, msg, Buffer.from(oracle.curve.calculateSignature(theirs.privKey, msg))), true);
        assert.ok(oracle.curve.verifySignature(ours.pubKey, msg, curve.calculateSignature(ours.privKey, msg)));
        assert.deepEqual(curve.calculateAgreement(theirs.pubKey, ours.privKey), Buffer.from(oracle.curve.calculateAgreement(ours.pubKey, theirs.privKey)));
    }
});

test('XEdDSA rejects malformed signatures and keys', () => {
    const { pubKey, privKey } = curve.generateKeyPair();
    const msg = Buffer.from('m');
    const sig = curve.calculateSignature(privKey, msg);
    assert.throws(() => curve.verifySignature(pubKey, msg, sig.subarray(0, 63)));
    assert.throws(() => curve.verifySignature(pubKey, msg, Buffer.concat([sig, Buffer.from([0])])));
    const bigS = Buffer.from(sig); bigS.fill(0xff, 32, 63); bigS[63] = 0x7f;   // s >= q
    assert.throws(() => curve.verifySignature(pubKey, msg, bigS));
    const uTooBig = Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0xff)]); uTooBig[32] = 0x7f;   // u >= p
    assert.throws(() => curve.verifySignature(uTooBig, msg, sig));
    assert.throws(() => curve.verifySignature(Buffer.concat([Buffer.from([4]), pubKey.subarray(1)]), msg, sig));   // wrong type byte
});
