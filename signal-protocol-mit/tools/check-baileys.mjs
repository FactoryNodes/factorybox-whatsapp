// Copyright (c) 2026 Vicente Zaragoza Arnau. MIT licence (see LICENSE).
//
// Baileys 7 with whatever is installed as `libsignal` (this package, or libsignal-node to compare): two in-memory accounts talk
// through Baileys' own Signal repository (makeLibSignalRepository), as the socket does with real messages. Run it from the folder
// of the WhatsApp process (next to its node_modules): `node check-baileys.mjs` (README, "Checking it with your Baileys").
import assert from 'node:assert/strict';
import { makeLibSignalRepository } from '@whiskeysockets/baileys/lib/Signal/libsignal.js';
import { initAuthCreds, addTransactionCapability } from '@whiskeysockets/baileys/lib/Utils/auth-utils.js';
import { Curve, generateSignalPubKey } from '@whiskeysockets/baileys/lib/Utils/crypto.js';
import { createRequire } from 'node:module';

const lib = createRequire(import.meta.url).resolve('libsignal');
console.log('libsignal:', lib);
const warnings = [];
const logger = {
    level: 'silent', trace() {}, debug() {}, info() {},
    warn: (...a) => warnings.push(a), error: (...a) => warnings.push(a), child() { return logger; }
};

function party(jid) {
    const creds = initAuthCreds();
    const data = {};
    const store = {
        get: async (type, ids) => Object.fromEntries(ids.filter((id) => data[type]?.[id] !== undefined).map((id) => [id, data[type][id]])),
        set: async (d) => {
            for (const type of Object.keys(d)) {
                data[type] ??= {};
                for (const [id, v] of Object.entries(d[type])) {
                    if (v === null || v === undefined) delete data[type][id];
                    else data[type][id] = v;
                }
            }
        }
    };
    const keys = addTransactionCapability(store, logger, { maxCommitRetries: 3, delayBetweenTriesMs: 10 });
    const pre = Curve.generateKeyPair();
    data['pre-key'] = { 1: pre };
    const repo = makeLibSignalRepository({ creds, keys }, logger, async () => null);
    const bundle = () => ({
        registrationId: creds.registrationId,
        identityKey: generateSignalPubKey(creds.signedIdentityKey.public),
        signedPreKey: { keyId: creds.signedPreKey.keyId, publicKey: generateSignalPubKey(creds.signedPreKey.keyPair.public),
            signature: creds.signedPreKey.signature },
        preKey: { keyId: 1, publicKey: generateSignalPubKey(pre.public) }
    });
    return { jid, creds, data, repo, bundle };
}

const text = (b) => Buffer.from(b).toString('utf8');
const alice = party('34600111222@s.whatsapp.net');
const bob = party('34600333444@s.whatsapp.net');

// 1:1: Alice empieza con el paquete de claves de Bob (lo que hace el socket tras pedírselo al servidor)
await alice.repo.injectE2ESession({ jid: bob.jid, session: bob.bundle() });
const m1 = await alice.repo.encryptMessage({ jid: bob.jid, data: Buffer.from('hola 1') });
const m2 = await alice.repo.encryptMessage({ jid: bob.jid, data: Buffer.from('hola 2') });
assert.deepEqual([m1.type, m2.type], ['pkmsg', 'pkmsg']);
assert.equal(text(await bob.repo.decryptMessage({ jid: alice.jid, type: m2.type, ciphertext: m2.ciphertext })), 'hola 2');   // desordenados
assert.equal(text(await bob.repo.decryptMessage({ jid: alice.jid, type: m1.type, ciphertext: m1.ciphertext })), 'hola 1');
// Baileys 7 lee la identidad del pkmsg con src/protobufs.js y la guarda (detección de cambio de identidad)
const savedIdentity = bob.data['identity-key']?.['34600111222.0'];
assert.ok(savedIdentity, 'Bob ha guardado la identidad de Alice');
assert.deepEqual(Buffer.from(savedIdentity), Buffer.from(generateSignalPubKey(alice.creds.signedIdentityKey.public)));
assert.equal(bob.data['pre-key']?.[1], undefined, 'la pre-clave de un solo uso se ha gastado');

const r1 = await bob.repo.encryptMessage({ jid: alice.jid, data: Buffer.from('adiós') });
assert.equal(r1.type, 'msg');
assert.equal(text(await alice.repo.decryptMessage({ jid: bob.jid, type: r1.type, ciphertext: r1.ciphertext })), 'adiós');
const m3 = await alice.repo.encryptMessage({ jid: bob.jid, data: Buffer.from('ya normal') });
assert.equal(m3.type, 'msg');
assert.equal(text(await bob.repo.decryptMessage({ jid: alice.jid, type: m3.type, ciphertext: m3.ciphertext })), 'ya normal');
for (let i = 0; i < 5; i++) {
    const a = await alice.repo.encryptMessage({ jid: bob.jid, data: Buffer.from(`a${i}`) });
    assert.equal(text(await bob.repo.decryptMessage({ jid: alice.jid, type: a.type, ciphertext: a.ciphertext })), `a${i}`);
    const b = await bob.repo.encryptMessage({ jid: alice.jid, data: Buffer.from(`b${i}`) });
    assert.equal(text(await alice.repo.decryptMessage({ jid: bob.jid, type: b.type, ciphertext: b.ciphertext })), `b${i}`);
}

// getSessionInfo (los reintentos de Baileys 7): la misma clave base en los dos lados y el registro del otro
const ia = await alice.repo.getSessionInfo(bob.jid), ib = await bob.repo.getSessionInfo(alice.jid);
assert.ok(ia && ib, 'getSessionInfo da la sesión');
assert.equal(ia.registrationId, bob.creds.registrationId);
assert.equal(ib.registrationId, alice.creds.registrationId);
assert.deepEqual(Buffer.from(ia.baseKey), Buffer.from(ib.baseKey));
assert.deepEqual(await alice.repo.validateSession(bob.jid), { exists: true });

// Grupos: las claves de remitente son de Baileys, con curve y crypto de la librería
const group = '120363000000000000@g.us';
const g1 = await alice.repo.encryptGroupMessage({ group, meId: alice.jid, data: Buffer.from('al grupo 1') });
await bob.repo.processSenderKeyDistributionMessage({
    item: { groupId: group, axolotlSenderKeyDistributionMessage: g1.senderKeyDistributionMessage }, authorJid: alice.jid
});
assert.equal(text(await bob.repo.decryptGroupMessage({ group, authorJid: alice.jid, msg: g1.ciphertext })), 'al grupo 1');
const g2 = await alice.repo.encryptGroupMessage({ group, meId: alice.jid, data: Buffer.from('al grupo 2') });
assert.equal(text(await bob.repo.decryptGroupMessage({ group, authorJid: alice.jid, msg: g2.ciphertext })), 'al grupo 2');

// Un mensaje cambiado no pasa
const bad = await alice.repo.encryptMessage({ jid: bob.jid, data: Buffer.from('cambiado') });
const tampered = Buffer.from(bad.ciphertext); tampered[tampered.length - 3] ^= 1;
await assert.rejects(bob.repo.decryptMessage({ jid: alice.jid, type: bad.type, ciphertext: tampered }));
assert.equal(text(await bob.repo.decryptMessage({ jid: alice.jid, type: bad.type, ciphertext: bad.ciphertext })), 'cambiado');

// Borrar la sesión (lo hace Baileys al rehacerla)
await alice.repo.deleteSession([bob.jid]);
assert.equal((await alice.repo.validateSession(bob.jid)).exists, false);

const uniq = [...new Set(warnings.map((w) => JSON.stringify(w).slice(0, 160)))];
for (const w of uniq.slice(0, 4)) console.log('Baileys says:', w);
console.log(`All good: one-to-one both ways, getSessionInfo, groups, a tampered message and deleting a session (${warnings.length} warnings from Baileys, expected without a server).`);
