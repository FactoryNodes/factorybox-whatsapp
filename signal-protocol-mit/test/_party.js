// A party in a conversation, with an in-memory store shaped like the one Baileys gives libsignal (its signalStorage):
// identity key with a 33-byte public key, one-time and signed pre-keys with 32-byte public keys, records stored as
// whatever SessionRecord.serialize() returns and read back with SessionRecord.deserialize().
export function makeParty(lib, name, { oneTimePreKey = true } = {}) {
    const raw = (pub) => Buffer.from(pub).subarray(1);
    const identity = lib.curve.generateKeyPair();
    const signed = lib.curve.generateKeyPair();
    const signedPreKey = { keyId: 7, pub: raw(signed.pubKey), priv: Buffer.from(signed.privKey),
        signature: Buffer.from(lib.curve.calculateSignature(identity.privKey, signed.pubKey)) };
    const preKeys = new Map();
    if (oneTimePreKey) {
        const k = lib.curve.generateKeyPair();
        preKeys.set(31, { pub: raw(k.pubKey), priv: Buffer.from(k.privKey) });
    }
    const sessions = new Map();
    const registrationId = 1000 + Math.floor(Math.random() * 1000);

    const storage = {
        loadSession: async (id) => (sessions.has(id) ? lib.SessionRecord.deserialize(sessions.get(id)) : undefined),
        storeSession: async (id, record) => { sessions.set(id, record.serialize()); },
        isTrustedIdentity: () => true,
        loadPreKey: async (id) => {
            const k = preKeys.get(Number(id));
            return k && { privKey: k.priv, pubKey: k.pub };
        },
        removePreKey: async (id) => { preKeys.delete(Number(id)); },
        loadSignedPreKey: () => ({ privKey: signedPreKey.priv, pubKey: signedPreKey.pub }),
        getOurRegistrationId: () => registrationId,
        getOurIdentity: () => ({ privKey: Buffer.from(identity.privKey), pubKey: Buffer.from(identity.pubKey) })
    };

    const bundle = () => ({
        registrationId,
        identityKey: Buffer.from(identity.pubKey),
        signedPreKey: { keyId: signedPreKey.keyId, publicKey: Buffer.concat([Buffer.from([5]), signedPreKey.pub]), signature: signedPreKey.signature },
        preKey: preKeys.has(31) ? { keyId: 31, publicKey: Buffer.concat([Buffer.from([5]), preKeys.get(31).pub]) } : undefined
    });

    const cipher = (other) => new lib.SessionCipher(storage, new lib.ProtocolAddress(other, 1));
    return {
        name, lib, storage, bundle, preKeys, sessions,
        start: (other, theirBundle) => new lib.SessionBuilder(storage, new lib.ProtocolAddress(other, 1)).initOutgoing(theirBundle),
        send: async (other, text) => {
            const { type, body } = await cipher(other).encrypt(Buffer.from(text));
            return { type, body: Buffer.from(body, 'binary') };   // as Baileys reads it
        },
        receive: async (other, { type, body }) => {
            const c = cipher(other);
            const plain = type === 3 ? await c.decryptPreKeyWhisperMessage(body) : await c.decryptWhisperMessage(body);
            return Buffer.from(plain).toString();
        }
    };
}
