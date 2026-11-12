import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import * as crypto from '../src/crypto.js';
import { oracle } from './_oracle.js';

test('HKDF: RFC 5869, test case 1', () => {
    const ikm = Buffer.alloc(22, 0x0b);
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
    const okm = Buffer.concat(crypto.deriveSecrets(ikm, salt, info, 2)).subarray(0, 42);
    assert.equal(okm.toString('hex'), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

test('AES-256-CBC and HMAC-SHA256 round trip', () => {
    const key = crypto.getRandomBytes(32), iv = crypto.getRandomBytes(16);
    const data = Buffer.from('texto de prueba que ocupa más de un bloque');
    assert.deepEqual(crypto.decrypt(key, crypto.encrypt(key, data, iv), iv), data);
    assert.equal(crypto.calculateMAC(key, data).length, 32);
    assert.throws(() => crypto.verifyMAC(data, key, Buffer.alloc(8), 8));
});

test('interop: the same results as the black box (deriveSecrets, encrypt, calculateMAC)', { skip: !oracle && 'no oracle' }, () => {
    const theirs = createRequire(import.meta.url)(join(process.env.LIBSIGNAL_ORACLE ?? join(import.meta.dirname, '..', '..', '..', 'build',
        'factorybox-whatsapp-cache', 'sidecar', 'node_modules', 'libsignal'), 'src', 'crypto.js'));
    const input = crypto.getRandomBytes(32), salt = crypto.getRandomBytes(32), info = Buffer.from('WhisperGroup');
    assert.deepEqual(crypto.deriveSecrets(input, salt, info).map((b) => b.toString('hex')),
        theirs.deriveSecrets(input, salt, info).map((b) => Buffer.from(b).toString('hex')));
    const key = crypto.getRandomBytes(32), iv = crypto.getRandomBytes(16), data = Buffer.from('mensaje del grupo');
    assert.deepEqual(crypto.encrypt(key, data, iv), Buffer.from(theirs.encrypt(key, data, iv)));
    assert.deepEqual(crypto.calculateMAC(key, data), Buffer.from(theirs.calculateMAC(key, data)));
});
