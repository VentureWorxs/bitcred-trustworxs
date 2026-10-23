// Prints a new private ES256 JWK for the ISSUER_JWK secret. Pipe it straight into
// `wrangler secret put ISSUER_JWK` so the key never lands in a file or the shell history.
import { generateKeyPair } from './common.js';

const { privateKey } = await generateKeyPair();
process.stdout.write(JSON.stringify(privateKey));
