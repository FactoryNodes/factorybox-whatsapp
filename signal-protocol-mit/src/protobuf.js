// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Vicente Zaragoza Arnau
//
// The two wire messages, as WhatsApp defines them in its protocol schema (WAProto.proto, shipped with Baileys under the
// MIT licence):
//
//   message SignalMessage       { bytes ratchetKey = 1; uint32 counter = 2; uint32 previousCounter = 3; bytes ciphertext = 4; }
//   message PreKeySignalMessage { uint32 registrationId = 5; uint32 preKeyId = 1; uint32 signedPreKeyId = 6;
//                                 bytes baseKey = 2; bytes identityKey = 3; bytes message = 4; }
//
// A minimal protocol buffers codec (varint and length-delimited fields only), so no dependency is needed.

const VARINT = 0, LENGTH = 2;

function writeVarint(out, value) {
    let v = value >>> 0;
    while (v > 0x7f) {
        out.push((v & 0x7f) | 0x80);
        v >>>= 7;
    }
    out.push(v);
}

function encode(fields) {
    const out = [];
    for (const [number, type, value] of fields) {
        if (value === undefined || value === null) continue;
        writeVarint(out, (number << 3) | type);
        if (type === VARINT) writeVarint(out, value);
        else {
            const bytes = Buffer.from(value);
            writeVarint(out, bytes.length);
            for (const b of bytes) out.push(b);
        }
    }
    return Buffer.from(out);
}

function decode(buffer) {
    const data = Buffer.from(buffer);
    const fields = new Map();
    let i = 0;
    const varint = () => {
        let result = 0, shift = 0, byte;
        do {
            if (i >= data.length) throw new Error('Truncated protobuf');
            byte = data[i++];
            if (shift < 32) result |= (byte & 0x7f) << shift;
            shift += 7;
        } while (byte & 0x80);
        return result >>> 0;
    };
    while (i < data.length) {
        const key = varint();
        const number = key >>> 3, type = key & 7;
        if (type === VARINT) fields.set(number, varint());
        else if (type === LENGTH) {
            const length = varint();
            if (i + length > data.length) throw new Error('Truncated protobuf');
            fields.set(number, data.subarray(i, i + length));
            i += length;
        } else if (type === 1) i += 8;
        else if (type === 5) i += 4;
        else throw new Error(`Unsupported protobuf wire type ${type}`);
    }
    return fields;
}

export const SignalMessage = {
    encode: ({ ratchetKey, counter, previousCounter, ciphertext }) =>
        encode([[1, LENGTH, ratchetKey], [2, VARINT, counter], [3, VARINT, previousCounter], [4, LENGTH, ciphertext]]),
    decode: (bytes) => {
        const f = decode(bytes);
        return { ratchetKey: f.get(1), counter: f.get(2) ?? 0, previousCounter: f.get(3) ?? 0, ciphertext: f.get(4) };
    }
};

export const PreKeySignalMessage = {
    encode: ({ registrationId, preKeyId, signedPreKeyId, baseKey, identityKey, message }) =>
        encode([[5, VARINT, registrationId], [1, VARINT, preKeyId], [6, VARINT, signedPreKeyId], [2, LENGTH, baseKey],
            [3, LENGTH, identityKey], [4, LENGTH, message]]),
    decode: (bytes) => {
        const f = decode(bytes);
        return {
            registrationId: f.get(5) ?? 0, preKeyId: f.get(1), signedPreKeyId: f.get(6) ?? 0,
            baseKey: f.get(2), identityKey: f.get(3), message: f.get(4)
        };
    }
};
