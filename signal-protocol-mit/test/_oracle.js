// Black box for the interoperability tests: the original libsignal-node, if it is installed next to the box sidecar
// cache (build/factorybox-whatsapp-cache). Only called (inputs and outputs), never read. Not published with the package.
import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const path = process.env.LIBSIGNAL_ORACLE ?? join(here, '..', '..', '..', 'build', 'factorybox-whatsapp-cache', 'sidecar', 'node_modules', 'libsignal');
export const oracle = existsSync(path) ? createRequire(import.meta.url)(path) : null;

/** Where the black box is (for its other files, like src/protobufs.js). */
export const oraclePath = () => path;
