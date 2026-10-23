// SD-JWT VC walkthrough: issue, request, present, verify, then attack tests.
// Run with `npm run demo`. Exits non-zero if any check does not behave as expected.
import { randomUUID } from 'node:crypto';
import type { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import {
  ISSUER,
  VERIFIER,
  VCT,
  createHolder,
  createIssuer,
  createVerifier,
  generateKeyPair,
  nowSeconds,
} from './common.js';

type Verifier = SDJwtVcInstance;
type Request = { nonce: string; aud: string };

let failures = 0;
const check = (label: string, ok: boolean, detail = '') => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ` (${detail})` : ''}`);
};

// Strict verification: pin issuer, type, nonce and audience, and require a key-binding JWT.
// Without keyBindingNonce and expectedKeyBindingAudience, verify() does not check key binding,
// and a credential presented with no KB-JWT at all is accepted.
async function verifyStrict(verifier: Verifier, presentation: string, request: Request) {
  const result = await verifier.verify(presentation, {
    expectedIssuer: ISSUER,
    expectedVct: VCT,
    keyBindingNonce: request.nonce,
    expectedKeyBindingAudience: request.aud,
    keyBindingMaxAgeSeconds: 300,
    disableStatusVerification: true, // no status list yet; see README
  });
  if (!result.kb) throw new Error('presentation has no key-binding JWT');
  return result;
}

// Returns the error message if verification fails, or null if the presentation was accepted.
async function rejectionOf(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

const newRequest = (aud = VERIFIER): Request => ({ nonce: randomUUID(), aud });

async function main() {
  const issuerKeys = await generateKeyPair();
  const holderKeys = await generateKeyPair();
  const attackerKeys = await generateKeyPair();

  const issuer = await createIssuer(issuerKeys);
  const holder = await createHolder(holderKeys);
  const attacker = await createHolder(attackerKeys);
  const verifier = await createVerifier(issuerKeys.publicKey);

  // 1. Issue: a membership credential bound to the holder's public key.
  // Synthetic data only; no PHI.
  console.log('\n1. Issue');
  const iat = nowSeconds();
  const credential = await issuer.issue(
    {
      iss: ISSUER,
      vct: VCT,
      iat,
      exp: iat + 3600,
      cnf: { jwk: holderKeys.publicKey },
      given_name: 'Alex',
      family_name: 'Example',
      member_id: 'M-000123',
      tier: 'gold',
      organization: 'Trustworxs Demo Co-op',
    },
    { _sd: ['given_name', 'family_name', 'member_id', 'tier', 'organization'] },
  );
  console.log(`  credential with ${credential.split('~').length - 2} selectively disclosable claims`);

  // 2. Request: the verifier sends a fresh nonce and its own identifier as audience.
  console.log('\n2. Request');
  const request = newRequest();
  console.log(`  nonce=${request.nonce} aud=${request.aud}`);

  // 3. Present: disclose only tier and organization, signed with the holder's key.
  console.log('\n3. Present');
  const presentation = await holder.present(
    credential,
    { tier: true, organization: true },
    { kb: { payload: { iat: nowSeconds(), aud: request.aud, nonce: request.nonce } } },
  );
  console.log(`  disclosed: tier, organization`);

  // 4. Verify (control): the honest presentation must pass and reveal only what was disclosed.
  console.log('\n4. Verify (control)');
  const err = await rejectionOf(() => verifyStrict(verifier, presentation, request));
  check('honest presentation accepted', err === null, err ?? '');
  if (err === null) {
    const { payload } = await verifyStrict(verifier, presentation, request);
    check('only disclosed claims revealed', payload.tier === 'gold' && payload.member_id === undefined);
  }

  console.log('\n5. Attacks');

  // A1. Stolen credential, no key binding. Default verify() accepts it; verifyStrict must not.
  const stolen = await attacker.present(credential, { tier: true, organization: true });
  const lax = await rejectionOf(() =>
    verifier.verify(stolen, { disableStatusVerification: true }),
  );
  console.log(`  note  default verify() on stolen credential: ${lax === null ? 'ACCEPTED' : 'rejected'}`);
  const a1 = await rejectionOf(() => verifyStrict(verifier, stolen, request));
  check('A1 stolen credential without KB-JWT rejected', a1 !== null, a1 ?? '');

  // A2. Stolen credential with a KB-JWT signed by the attacker's own key.
  const forgedKb = await attacker.present(
    credential,
    { tier: true },
    { kb: { payload: { iat: nowSeconds(), aud: request.aud, nonce: request.nonce } } },
  );
  const a2 = await rejectionOf(() => verifyStrict(verifier, forgedKb, request));
  check('A2 KB-JWT signed by wrong key rejected', a2 !== null, a2 ?? '');

  // A3. Replay: an earlier valid presentation reused against a new request (new nonce).
  const a3 = await rejectionOf(() => verifyStrict(verifier, presentation, newRequest()));
  check('A3 replayed presentation rejected', a3 !== null, a3 ?? '');

  // A4. Forwarding: a presentation made for this verifier sent to a different one.
  const other = newRequest('https://other-verifier.example');
  const forwarded = await holder.present(
    credential,
    { tier: true },
    { kb: { payload: { iat: nowSeconds(), aud: request.aud, nonce: other.nonce } } },
  );
  const a4 = await rejectionOf(() => verifyStrict(verifier, forwarded, other));
  check('A4 presentation for another audience rejected', a4 !== null, a4 ?? '');

  // A5. Tampered disclosure: change tier from gold to platinum after issuance.
  const parts = presentation.split('~');
  const idx = parts.findIndex((p, i) => {
    if (i === 0 || i === parts.length - 1 || !p) return false;
    return Buffer.from(p, 'base64url').toString().includes('"tier"');
  });
  const decoded = JSON.parse(Buffer.from(parts[idx], 'base64url').toString());
  decoded[2] = 'platinum';
  parts[idx] = Buffer.from(JSON.stringify(decoded)).toString('base64url');
  const a5 = await rejectionOf(() => verifyStrict(verifier, parts.join('~'), request));
  check('A5 tampered disclosure rejected', a5 !== null, a5 ?? '');

  console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) failed.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
