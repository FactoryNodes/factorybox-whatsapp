import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as ours from '../index.js';
import { oracle } from './_oracle.js';
import { makeParty } from './_party.js';

/** A conversation: pre-key messages until the first answer, then normal ones; out of order on both sides. */
async function conversation(aliceLib, bobLib, options = {}) {
    const alice = makeParty(aliceLib, 'alice');
    const bob = makeParty(bobLib, 'bob', options);
    await alice.start('bob', bob.bundle());

    const a1 = await alice.send('bob', 'hola 1');
    const a2 = await alice.send('bob', 'hola 2');
    const a3 = await alice.send('bob', 'hola 3');
    assert.deepEqual([a1.type, a2.type, a3.type], [3, 3, 3]);
    assert.equal(await bob.receive('alice', a3), 'hola 3');   // out of order: the third first
    assert.equal(await bob.receive('alice', a1), 'hola 1');
    if (options.oneTimePreKey !== false) assert.equal(bob.preKeys.size, 0);   // the one-time pre-key is used up
    assert.equal(await bob.receive('alice', a2), 'hola 2');

    const b1 = await bob.send('alice', 'adiós 1');
    const b2 = await bob.send('alice', 'adiós 2');
    assert.equal(b1.type, 1);
    assert.equal(await alice.receive('bob', b2), 'adiós 2');
    assert.equal(await alice.receive('bob', b1), 'adiós 1');

    const a4 = await alice.send('bob', 'ya normal');
    assert.equal(a4.type, 1);   // Bob answered: no more pre-key messages
    assert.equal(await bob.receive('alice', a4), 'ya normal');

    // Several ratchet steps in a row, and a late message from an earlier step
    const late = await alice.send('bob', 'tarde');
    for (let i = 0; i < 3; i++) {
        assert.equal(await bob.receive('alice', await alice.send('bob', `a${i}`)), `a${i}`);
        assert.equal(await alice.receive('bob', await bob.send('alice', `b${i}`)), `b${i}`);
    }
    assert.equal(await bob.receive('alice', late), 'tarde');
    return { alice, bob };
}

test('ours with ours: X3DH, pre-key messages, ratchet steps and messages out of order', async () => {
    await conversation(ours, ours);
});

test('ours with ours without a one-time pre-key (DH4 is optional)', async () => {
    await conversation(ours, ours, { oneTimePreKey: false });
});

test('a tampered message is rejected and changes nothing', async () => {
    const alice = makeParty(ours, 'alice'), bob = makeParty(ours, 'bob');
    await alice.start('bob', bob.bundle());
    assert.equal(await bob.receive('alice', await alice.send('bob', 'uno')), 'uno');
    const good = await alice.send('bob', 'dos');
    const bad = { type: good.type, body: Buffer.from(good.body) };
    bad.body[bad.body.length - 20] ^= 1;
    await assert.rejects(bob.receive('alice', bad));
    assert.equal(await bob.receive('alice', good), 'dos');
    await assert.rejects(bob.receive('alice', good));   // the same message twice
});

test('a session record survives serialize and deserialize, and a foreign record reads as empty', async () => {
    const alice = makeParty(ours, 'alice'), bob = makeParty(ours, 'bob');
    await alice.start('bob', bob.bundle());
    const stored = alice.sessions.get('bob.1');
    assert.equal(ours.SessionRecord.deserialize(stored).serialize(), stored);
    assert.equal(ours.SessionRecord.deserialize({ _sessions: {}, version: 'v1' }).haveOpenSession(), false);
});

test('interop: ours starts, the black box answers', { skip: !oracle && 'no oracle' }, async () => {
    await conversation(ours, oracle);
});

test('interop: the black box starts, ours answers', { skip: !oracle && 'no oracle' }, async () => {
    await conversation(oracle, ours);
});

test('interop without a one-time pre-key, both ways', { skip: !oracle && 'no oracle' }, async () => {
    await conversation(ours, oracle, { oneTimePreKey: false });
    await conversation(oracle, ours, { oneTimePreKey: false });
});

test('MAX_SKIP: 2000 skipped messages are fine, more are rejected and change nothing', async () => {
    const alice = makeParty(ours, 'alice'), bob = makeParty(ours, 'bob');
    await alice.start('bob', bob.bundle());
    assert.equal(await bob.receive('alice', await alice.send('bob', 'primero')), 'primero');
    for (let i = 0; i < 2001; i++) await alice.send('bob', `perdido ${i}`);
    const far = await alice.send('bob', 'lejos');   // counter 2002: 2001 keys to skip
    await assert.rejects(bob.receive('alice', far), /skipped|decrypt/);
    const alice2 = makeParty(ours, 'alice2'), bob2 = makeParty(ours, 'bob2');
    await alice2.start('bob2', bob2.bundle());
    assert.equal(await bob2.receive('alice2', await alice2.send('bob2', 'primero')), 'primero');
    for (let i = 0; i < 1999; i++) await alice2.send('bob2', `perdido ${i}`);
    assert.equal(await bob2.receive('alice2', await alice2.send('bob2', 'justo')), 'justo');   // 1999 + 1 = 2000 skipped
});

test('both sides start a session at the same time and still talk', async () => {
    const alice = makeParty(ours, 'alice'), bob = makeParty(ours, 'bob');
    await alice.start('bob', bob.bundle());
    await bob.start('alice', alice.bundle());
    const fromAlice = await alice.send('bob', 'de alice'), fromBob = await bob.send('alice', 'de bob');
    assert.equal(await bob.receive('alice', fromAlice), 'de alice');
    assert.equal(await alice.receive('bob', fromBob), 'de bob');
    assert.equal(await bob.receive('alice', await alice.send('bob', 'otra')), 'otra');
    assert.equal(await alice.receive('bob', await bob.send('alice', 'otra más')), 'otra más');
});

test('an untrusted identity is refused on both sides', async () => {
    const alice = makeParty(ours, 'alice'), bob = makeParty(ours, 'bob');
    alice.storage.isTrustedIdentity = () => false;
    await assert.rejects(alice.start('bob', bob.bundle()), /Untrusted/);
    const carol = makeParty(ours, 'carol');
    await carol.start('bob', bob.bundle());
    bob.storage.isTrustedIdentity = () => false;
    await assert.rejects(bob.receive('carol', await carol.send('bob', 'hola')), /Untrusted/);
});

test('parallel encrypts get consecutive counters and all decrypt', async () => {
    const alice = makeParty(ours, 'alice'), bob = makeParty(ours, 'bob');
    await alice.start('bob', bob.bundle());
    const sent = await Promise.all(Array.from({ length: 10 }, (_, i) => alice.send('bob', `p${i}`)));
    const got = [];
    for (const m of sent) got.push(await bob.receive('alice', m));
    assert.deepEqual(got, Array.from({ length: 10 }, (_, i) => `p${i}`));
});

test('truncated, malformed and other-version messages fail with a clear error', async () => {
    const alice = makeParty(ours, 'alice'), bob = makeParty(ours, 'bob');
    await alice.start('bob', bob.bundle());
    const m = await alice.send('bob', 'hola');
    await assert.rejects(bob.receive('alice', { type: 3, body: m.body.subarray(0, 10) }));
    const v2 = Buffer.from(m.body); v2[0] = 0x22;
    await assert.rejects(bob.receive('alice', { type: 3, body: v2 }), /version/);
    await assert.rejects(bob.receive('alice', { type: 3, body: Buffer.from([0x33, 0x28, 0x01]) }), /Malformed/);
    assert.equal(await bob.receive('alice', m), 'hola');   // nothing changed
});

test('a forged message for an old (closed) receiving chain is rejected', async () => {
    const alice = makeParty(ours, 'alice'), bob = makeParty(ours, 'bob');
    await alice.start('bob', bob.bundle());
    assert.equal(await bob.receive('alice', await alice.send('bob', 'a0')), 'a0');
    const record0 = alice.sessions.get('bob.1');   // Alice's state with the first sending chain
    assert.equal(await alice.receive('bob', await bob.send('alice', 'b0')), 'b0');
    assert.equal(await bob.receive('alice', await alice.send('bob', 'a1')), 'a1');   // new ratchet step: chain 1 closed for Bob
    alice.sessions.set('bob.1', record0);   // an attacker with the old state keeps sending on the old chain
    const old = await alice.send('bob', 'viejo');
    await assert.rejects(bob.receive('alice', old));
});
