// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Vicente Zaragoza Arnau
//
// Sessions with X3DH ("The X3DH Key Agreement Protocol", Signal, rev. 1, 2016-11-04, public domain) and the Double
// Ratchet ("The Double Ratchet Algorithm", Signal, rev. 1, 2016-11-20, public domain). Section numbers in the comments
// refer to those documents. Where the specifications leave a choice to the application (info strings, wire format,
// message authentication), the values are the ones WhatsApp uses, listed in PROVENANCE.md.
//
// The public surface is the subset of libsignal-node that Baileys calls: ProtocolAddress, SessionRecord, SessionBuilder
// (initOutgoing) and SessionCipher (encrypt, decryptPreKeyWhisperMessage, decryptWhisperMessage), with the same storage
// interface (loadSession, storeSession, isTrustedIdentity, loadPreKey, removePreKey, loadSignedPreKey,
// getOurRegistrationId, getOurIdentity).

import * as curve from './curve.js';
import { deriveSecrets, calculateMAC, encrypt, decrypt, verifyMAC } from './crypto.js';
import { SignalMessage, PreKeySignalMessage } from './protobuf.js';

// ---------- Values the specifications leave to the application (PROVENANCE.md) ----------

const VERSION = 3;
const VERSION_BYTE = (VERSION << 4) | VERSION;       // 0x33: high nibble = message version, low nibble = current version
const MAC_LENGTH = 8;                                // the HMAC appended to a message is truncated to 8 bytes
const INFO_X3DH = Buffer.from('WhisperText');        // X3DH KDF info (X3DH 2.2)
const INFO_RATCHET = Buffer.from('WhisperRatchet');  // KDF_RK info (Double Ratchet 5.2)
const INFO_MESSAGE = Buffer.from('WhisperMessageKeys'); // ENCRYPT info (Double Ratchet 5.2)
const MESSAGE_KEY_SEED = Buffer.from([0x01]);        // KDF_CK: message key = HMAC(ck, 0x01) (Double Ratchet 5.2)
const CHAIN_KEY_SEED = Buffer.from([0x02]);          //         next chain key = HMAC(ck, 0x02)
const ZERO_SALT = Buffer.alloc(32);

const MAX_SKIP = 2000;          // Double Ratchet 3.5: how many message keys may be skipped in one chain
const MAX_SKIPPED_KEYS = 2000;  // Double Ratchet 8.4: skipped keys kept per session (the oldest go first)
const MAX_RECEIVING_CHAINS = 5; // receiving chains kept per session (late messages of earlier ratchet steps)
const MAX_SESSIONS = 40;        // archived sessions kept per address (the contact reinstalled, two sessions crossed…)

const b64 = (buf) => (buf ? Buffer.from(buf).toString('base64') : null);
const unb64 = (s) => (s ? Buffer.from(s, 'base64') : null);
const withType = (pub) => (Buffer.from(pub).length === 32 ? Buffer.concat([Buffer.from([curve.KEY_TYPE]), Buffer.from(pub)]) : Buffer.from(pub));
const same = (a, b) => !!a && !!b && Buffer.compare(withType(a), withType(b)) === 0;

// ---------- Addresses ----------

export class ProtocolAddress {
    constructor(name, deviceId) {
        if (typeof name !== 'string' || name.includes('.')) throw new Error('Invalid address name');
        this.name = name;
        this.deviceId = deviceId ?? 0;
    }

    static from(text) {
        const dot = text.lastIndexOf('.');
        return new ProtocolAddress(text.slice(0, dot), Number(text.slice(dot + 1)));
    }

    toString() {
        return `${this.name}.${this.deviceId}`;
    }

    is(other) {
        return other instanceof ProtocolAddress && other.name === this.name && other.deviceId === this.deviceId;
    }
}

// ---------- Key derivation (Double Ratchet 5.2) ----------

/** KDF_RK(rk, dh_out): HKDF with rk as salt; 64 bytes: new root key and chain key. */
function kdfRoot(rootKey, dhOut) {
    const [rk, ck] = deriveSecrets(dhOut, rootKey, INFO_RATCHET, 2);
    return { rootKey: rk, chainKey: ck };
}

/** KDF_CK(ck): the message key seed and the next chain key. */
function kdfChain(chainKey) {
    return { messageKey: calculateMAC(chainKey, MESSAGE_KEY_SEED), next: calculateMAC(chainKey, CHAIN_KEY_SEED) };
}

/** The 80 bytes that encrypt one message: AES key, MAC key and IV. */
function messageKeys(seed) {
    const [cipherKey, macKey, ivBlock] = deriveSecrets(seed, ZERO_SALT, INFO_MESSAGE, 3);
    return { cipherKey, macKey, iv: ivBlock.subarray(0, 16) };
}

// ---------- Session state ----------

class SessionState {
    constructor(fields) {
        Object.assign(this, {
            baseKey: null,               // the initiator's X3DH ephemeral key: identifies the session
            localIdentityKey: null,
            remoteIdentityKey: null,
            remoteRegistrationId: 0,
            rootKey: null,
            sending: null,               // { ratchetPub, ratchetPriv, chainKey, index }
            receiving: [],               // [{ ratchetPub, chainKey, index, skipped: { index: seed } }]
            previousCounter: 0,          // PN (Double Ratchet 3.2)
            pendingPreKey: null,         // { preKeyId, signedPreKeyId, baseKey } until the first answer arrives
            used: Date.now()
        }, fields);
    }

    /**
     * libsignal-node's names for two of these fields, which Baileys 7 reads from the open session (getSessionInfo) to notice a stale
     * session when a message is retried: the session's base key and the other side's registration id. Not stored twice.
     */
    get indexInfo() {
        return { baseKey: this.baseKey };
    }

    get registrationId() {
        return this.remoteRegistrationId;
    }

    clone() {
        return SessionState.fromJSON(this.toJSON());
    }

    toJSON() {
        return {
            baseKey: b64(this.baseKey), localIdentityKey: b64(this.localIdentityKey), remoteIdentityKey: b64(this.remoteIdentityKey),
            remoteRegistrationId: this.remoteRegistrationId, rootKey: b64(this.rootKey),
            sending: this.sending && { ratchetPub: b64(this.sending.ratchetPub), ratchetPriv: b64(this.sending.ratchetPriv),
                chainKey: b64(this.sending.chainKey), index: this.sending.index },
            receiving: this.receiving.map((c) => ({ ratchetPub: b64(c.ratchetPub), chainKey: b64(c.chainKey), index: c.index,
                skipped: Object.fromEntries(Object.entries(c.skipped).map(([k, v]) => [k, b64(v)])) })),
            previousCounter: this.previousCounter,
            pendingPreKey: this.pendingPreKey && { ...this.pendingPreKey, baseKey: b64(this.pendingPreKey.baseKey) },
            used: this.used
        };
    }

    static fromJSON(j) {
        return new SessionState({
            baseKey: unb64(j.baseKey), localIdentityKey: unb64(j.localIdentityKey), remoteIdentityKey: unb64(j.remoteIdentityKey),
            remoteRegistrationId: j.remoteRegistrationId ?? 0, rootKey: unb64(j.rootKey),
            sending: j.sending && { ratchetPub: unb64(j.sending.ratchetPub), ratchetPriv: unb64(j.sending.ratchetPriv),
                chainKey: unb64(j.sending.chainKey), index: j.sending.index },
            receiving: (j.receiving ?? []).map((c) => ({ ratchetPub: unb64(c.ratchetPub), chainKey: unb64(c.chainKey), index: c.index,
                skipped: Object.fromEntries(Object.entries(c.skipped ?? {}).map(([k, v]) => [k, unb64(v)])) })),
            previousCounter: j.previousCounter ?? 0,
            pendingPreKey: j.pendingPreKey && { ...j.pendingPreKey, baseKey: unb64(j.pendingPreKey.baseKey) },
            used: j.used ?? 0
        });
    }

    receivingChain(ratchetPub) {
        return this.receiving.find((c) => same(c.ratchetPub, ratchetPub));
    }

    /** Double Ratchet 3.5, DHRatchet: a new receiving chain for their key, then a new sending key and chain. */
    dhRatchet(theirRatchetPub) {
        this.previousCounter = this.sending ? this.sending.index : 0;
        const receive = kdfRoot(this.rootKey, curve.calculateAgreement(theirRatchetPub, this.sending.ratchetPriv));
        this.receiving.push({ ratchetPub: withType(theirRatchetPub), chainKey: receive.chainKey, index: 0, skipped: {} });
        if (this.receiving.length > MAX_RECEIVING_CHAINS) this.receiving.shift();
        const next = curve.generateKeyPair();
        const send = kdfRoot(receive.rootKey, curve.calculateAgreement(theirRatchetPub, next.privKey));
        this.rootKey = send.rootKey;
        this.sending = { ratchetPub: next.pubKey, ratchetPriv: next.privKey, chainKey: send.chainKey, index: 0 };
    }
}

// ---------- Session record: the sessions with one address ----------

export class SessionRecord {
    constructor() {
        this.sessions = [];   // the open (current) one first, then the archived ones, newest first
    }

    static deserialize(data) {
        const record = new SessionRecord();
        try {
            const json = typeof data === 'string' ? JSON.parse(data) : Buffer.isBuffer(data) ? JSON.parse(data.toString('utf8')) : data;
            // Only our own format: a record written by another library (other fields) is read as empty and the
            // session is built again with the next pre-key message (see README, "Switching from libsignal").
            if (json?.format === 'signal-protocol-mit/1') record.sessions = json.sessions.map(SessionState.fromJSON);
        } catch {
            record.sessions = [];
        }
        return record;
    }

    serialize() {
        return JSON.stringify({ format: 'signal-protocol-mit/1', sessions: this.sessions.map((s) => s.toJSON()) });
    }

    haveOpenSession() {
        return this.sessions.length > 0;
    }

    getOpenSession() {
        return this.sessions[0];
    }

    getSession(baseKey) {
        return this.sessions.find((s) => same(s.baseKey, baseKey));
    }

    /** The given session becomes the open one; the previous open one is archived (kept to decrypt late messages). */
    promote(session) {
        this.sessions = [session, ...this.sessions.filter((s) => s !== session && !same(s.baseKey, session.baseKey))].slice(0, MAX_SESSIONS);
    }

    deleteAllSessions() {
        this.sessions = [];
    }
}

// ---------- One operation at a time per address (concurrent encrypts or decrypts would fork the ratchet) ----------

const queues = new Map();

function serialized(address, job) {
    const key = address.toString();
    const previous = queues.get(key) ?? Promise.resolve();
    const run = previous.catch(() => {}).then(job);
    const tail = run.catch(() => {});
    queues.set(key, tail);
    tail.then(() => { if (queues.get(key) === tail) queues.delete(key); });
    return run;
}

// ---------- X3DH (sections 2.2 and 3.3) ----------

/** The master secret: F || DH1 || DH2 || DH3 [|| DH4], F = 32 bytes 0xFF for X25519 (X3DH 2.2). */
function masterSecret(dh) {
    return Buffer.concat([Buffer.alloc(32, 0xff), ...dh]);
}

function rootFromX3DH(dh) {
    const [rootKey, chainKey] = deriveSecrets(masterSecret(dh), ZERO_SALT, INFO_X3DH, 2);
    return { rootKey, chainKey };
}

async function ourIdentity(storage) {
    const identity = await storage.getOurIdentity();
    return { pubKey: withType(identity.pubKey), privKey: Buffer.from(identity.privKey) };
}

export class SessionBuilder {
    constructor(storage, remoteAddress) {
        this.storage = storage;
        this.address = remoteAddress;
    }

    /**
     * The initiator's side of X3DH (section 3.3) with the pre-key bundle the server gives:
     * { registrationId, identityKey, signedPreKey: { keyId, publicKey, signature }, preKey?: { keyId, publicKey } }.
     * Then the first ratchet step of the Double Ratchet (RatchetInitAlice, section 3.3 of the Double Ratchet).
     */
    initOutgoing(bundle) {
        return serialized(this.address, async () => {
            const identityKey = withType(bundle.identityKey);
            if (!(await this.storage.isTrustedIdentity(this.address.name, identityKey, 0))) throw new Error('Untrusted identity key');
            curve.verifySignature(identityKey, withType(bundle.signedPreKey.publicKey), bundle.signedPreKey.signature);

            const us = await ourIdentity(this.storage);
            const ephemeral = curve.generateKeyPair();
            const signedPreKey = withType(bundle.signedPreKey.publicKey);
            const dh = [
                curve.calculateAgreement(signedPreKey, us.privKey),               // DH1 = DH(IKA, SPKB)
                curve.calculateAgreement(identityKey, ephemeral.privKey),         // DH2 = DH(EKA, IKB)
                curve.calculateAgreement(signedPreKey, ephemeral.privKey)         // DH3 = DH(EKA, SPKB)
            ];
            if (bundle.preKey) dh.push(curve.calculateAgreement(withType(bundle.preKey.publicKey), ephemeral.privKey));   // DH4
            const { rootKey } = rootFromX3DH(dh);

            // RatchetInitAlice: a sending key and chain against their signed pre-key, which is their first ratchet key
            const ratchet = curve.generateKeyPair();
            const send = kdfRoot(rootKey, curve.calculateAgreement(signedPreKey, ratchet.privKey));
            const session = new SessionState({
                baseKey: ephemeral.pubKey, localIdentityKey: us.pubKey, remoteIdentityKey: identityKey,
                remoteRegistrationId: bundle.registrationId, rootKey: send.rootKey,
                sending: { ratchetPub: ratchet.pubKey, ratchetPriv: ratchet.privKey, chainKey: send.chainKey, index: 0 },
                pendingPreKey: { preKeyId: bundle.preKey?.keyId, signedPreKeyId: bundle.signedPreKey.keyId, baseKey: ephemeral.pubKey }
            });

            const record = (await this.storage.loadSession(this.address.toString())) ?? new SessionRecord();
            record.promote(session);
            await this.storage.storeSession(this.address.toString(), record);
        });
    }
}

// ---------- Encrypting and decrypting (Double Ratchet 3.4 and 3.5) ----------

export class SessionCipher {
    constructor(storage, remoteAddress) {
        this.storage = storage;
        this.address = remoteAddress;
    }

    async loadRecord() {
        return (await this.storage.loadSession(this.address.toString())) ?? null;
    }

    async getRemoteRegistrationId() {
        return (await this.loadRecord())?.getOpenSession()?.remoteRegistrationId;
    }

    async hasOpenSession() {
        return !!(await this.loadRecord())?.haveOpenSession();
    }

    /**
     * RatchetEncrypt. Returns { type: 3, body } (a pre-key message, while the other side has not answered yet) or
     * { type: 1, body } (a normal message); body is a binary string, as Baileys reads it.
     */
    encrypt(data) {
        return serialized(this.address, async () => {
            const record = await this.loadRecord();
            const session = record?.getOpenSession();
            if (!session) throw new Error('No open session');
            const { messageKey, next } = kdfChain(session.sending.chainKey);
            const keys = messageKeys(messageKey);
            const ciphertext = encrypt(keys.cipherKey, Buffer.from(data), keys.iv);
            const inner = Buffer.concat([Buffer.from([VERSION_BYTE]), SignalMessage.encode({
                ratchetKey: session.sending.ratchetPub, counter: session.sending.index,
                previousCounter: session.previousCounter, ciphertext
            })]);
            // ENCRYPT's MAC over AD || message, AD = Encode(IK sender) || Encode(IK receiver) (X3DH 3.3)
            const mac = calculateMAC(keys.macKey, Buffer.concat([session.localIdentityKey, session.remoteIdentityKey, inner])).subarray(0, MAC_LENGTH);
            const message = Buffer.concat([inner, mac]);
            session.sending.chainKey = next;
            session.sending.index += 1;
            session.used = Date.now();
            await this.storage.storeSession(this.address.toString(), record);

            if (!session.pendingPreKey) return { type: 1, body: message.toString('binary'), registrationId: session.remoteRegistrationId };
            const registrationId = await this.storage.getOurRegistrationId();
            const preKeyMessage = Buffer.concat([Buffer.from([VERSION_BYTE]), PreKeySignalMessage.encode({
                registrationId, preKeyId: session.pendingPreKey.preKeyId, signedPreKeyId: session.pendingPreKey.signedPreKeyId,
                baseKey: session.pendingPreKey.baseKey, identityKey: session.localIdentityKey, message
            })]);
            return { type: 3, body: preKeyMessage.toString('binary'), registrationId: session.remoteRegistrationId };
        });
    }

    /** A normal message, with the sessions already open (the current one first, then the archived ones). */
    decryptWhisperMessage(data) {
        return serialized(this.address, async () => {
            const record = await this.loadRecord();
            if (!record?.haveOpenSession()) throw new Error('No session record');
            const { plaintext, session } = decryptWithSessions(record, Buffer.from(data));
            if (!(await this.storage.isTrustedIdentity(this.address.name, session.remoteIdentityKey, 1))) throw new Error('Untrusted identity key');
            record.promote(session);
            await this.storage.storeSession(this.address.toString(), record);
            return plaintext;
        });
    }

    /**
     * A pre-key message: the responder's side of X3DH (section 3.3) if the session does not exist yet, then the
     * message inside it. The one-time pre-key it used is removed afterwards (X3DH 3.3: "deletes … one-time prekey").
     */
    decryptPreKeyWhisperMessage(data) {
        return serialized(this.address, async () => {
            const bytes = Buffer.from(data);
            if (bytes[0] >> 4 !== VERSION) throw new Error(`Unsupported pre-key message version ${bytes[0] >> 4}`);
            const message = PreKeySignalMessage.decode(bytes.subarray(1));
            if (!message.baseKey || !message.identityKey || !message.message) throw new Error('Malformed pre-key message');
            const identityKey = withType(message.identityKey);
            if (!(await this.storage.isTrustedIdentity(this.address.name, identityKey, 1))) throw new Error('Untrusted identity key');

            const record = (await this.loadRecord()) ?? new SessionRecord();
            let session = record.getSession(message.baseKey)?.clone();   // a copy: nothing changes if it fails
            if (session && !same(session.remoteIdentityKey, identityKey)) throw new Error('Identity key does not match the session');
            const isNew = !session;
            if (isNew) session = await this.respondX3DH(message, identityKey);
            const plaintext = decryptMessage(session, Buffer.from(message.message));
            record.promote(session);
            await this.storage.storeSession(this.address.toString(), record);
            if (isNew && message.preKeyId !== undefined) await this.storage.removePreKey(message.preKeyId);
            return plaintext;
        });
    }

    async respondX3DH(message, identityKey) {
        const signedPreKey = await this.storage.loadSignedPreKey(message.signedPreKeyId);
        if (!signedPreKey) throw new Error('Missing signed pre-key');
        const preKey = message.preKeyId !== undefined ? await this.storage.loadPreKey(message.preKeyId) : undefined;
        if (message.preKeyId !== undefined && !preKey) throw new Error('Missing one-time pre-key');
        const us = await ourIdentity(this.storage);
        const baseKey = withType(message.baseKey);
        const dh = [
            curve.calculateAgreement(identityKey, signedPreKey.privKey),   // DH1 = DH(SPKB, IKA)
            curve.calculateAgreement(baseKey, us.privKey),                 // DH2 = DH(IKB, EKA)
            curve.calculateAgreement(baseKey, signedPreKey.privKey)        // DH3 = DH(SPKB, EKA)
        ];
        if (preKey) dh.push(curve.calculateAgreement(baseKey, preKey.privKey));   // DH4 = DH(OPKB, EKA)
        const { rootKey } = rootFromX3DH(dh);
        // RatchetInitBob: our ratchet key pair is the signed pre-key; no chains until their first message
        return new SessionState({
            baseKey, localIdentityKey: us.pubKey, remoteIdentityKey: identityKey, remoteRegistrationId: message.registrationId,
            rootKey, sending: { ratchetPub: withType(signedPreKey.pubKey), ratchetPriv: Buffer.from(signedPreKey.privKey), chainKey: null, index: 0 }
        });
    }
}

/** Tries the sessions in order on copies, and keeps the one that decrypts (RatchetDecrypt never half-applied). */
function decryptWithSessions(record, data) {
    const errors = [];
    for (const original of record.sessions) {
        const session = original.clone();
        try {
            const plaintext = decryptMessage(session, data);
            record.sessions[record.sessions.indexOf(original)] = session;
            return { plaintext, session };
        } catch (error) {
            errors.push(error.message);
        }
    }

    throw new Error(`No session could decrypt the message (${errors.join('; ')})`);
}

/** RatchetDecrypt (Double Ratchet 3.5) on one session; throws without a valid MAC. Changes the session it is given. */
function decryptMessage(session, data) {
    if (data.length < 1 + MAC_LENGTH) throw new Error('Message too short');
    if (data[0] >> 4 !== VERSION) throw new Error(`Unsupported message version ${data[0] >> 4}`);
    const inner = data.subarray(0, data.length - MAC_LENGTH);
    const mac = data.subarray(data.length - MAC_LENGTH);
    const message = SignalMessage.decode(inner.subarray(1));
    if (!message.ratchetKey || !message.ciphertext) throw new Error('Malformed message');
    const ratchetPub = withType(message.ratchetKey);

    let chain = session.receivingChain(ratchetPub);
    let seed;
    if (chain && chain.skipped[message.counter]) {
        seed = chain.skipped[message.counter];                    // TrySkippedMessageKeys
        delete chain.skipped[message.counter];
    } else {
        if (!chain) {
            // A new ratchet key: skip what is left of the current receiving chain, then a DH ratchet step
            const current = session.receiving[session.receiving.length - 1];
            if (current) {
                skipMessageKeys(current, message.previousCounter);
                current.chainKey = null;   // closed: only its skipped keys remain (the spec replaces CKr)
            }
            session.dhRatchet(ratchetPub);
            chain = session.receivingChain(ratchetPub);
        }

        if (!chain.chainKey) throw new Error('Message for a closed chain');
        if (message.counter < chain.index) throw new Error('Duplicate or too old message');
        skipMessageKeys(chain, message.counter);
        const step = kdfChain(chain.chainKey);
        seed = step.messageKey;
        chain.chainKey = step.next;
        chain.index += 1;
    }

    const keys = messageKeys(seed);
    verifyMAC(Buffer.concat([session.remoteIdentityKey, session.localIdentityKey, inner]), keys.macKey, mac, MAC_LENGTH);
    const plaintext = decrypt(keys.cipherKey, message.ciphertext, keys.iv);
    session.pendingPreKey = null;   // they answered: no more pre-key messages
    session.used = Date.now();
    pruneSkippedKeys(session);
    return plaintext;
}

/** Double Ratchet 8.4: a limit on the skipped keys a session keeps; the ones of the oldest chains go first. */
function pruneSkippedKeys(session) {
    let total = session.receiving.reduce((n, c) => n + Object.keys(c.skipped).length, 0);
    for (const chain of session.receiving) {
        for (const index of Object.keys(chain.skipped).map(Number).sort((x, y) => x - y)) {
            if (total <= MAX_SKIPPED_KEYS) return;
            delete chain.skipped[index];
            total -= 1;
        }
    }
}

/** SkipMessageKeys (Double Ratchet 3.5): keeps the keys of the messages not received yet, up to MAX_SKIP. */
function skipMessageKeys(chain, until) {
    if (until - chain.index > MAX_SKIP) throw new Error('Too many skipped messages');
    while (chain.index < until) {
        const step = kdfChain(chain.chainKey);
        chain.skipped[chain.index] = step.messageKey;
        chain.chainKey = step.next;
        chain.index += 1;
    }
}
