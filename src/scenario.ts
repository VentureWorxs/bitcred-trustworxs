// SD-JWT VC walkthrough: issue, request, present, verify, then attack tests.
// Returns a report instead of printing, so the CLI (demo.ts) and the Worker (worker.ts) share it.
import type { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import {
  VERIFIER,
  VCT,
  base64urlDecode,
  base64urlEncode,
  createHolder,
  createIssuer,
  createVerifier,
  generateKeyPair,
  nowSeconds,
  type KeyPair,
} from './common.js';

type Verifier = SDJwtVcInstance;
type Request = { nonce: string; aud: string };

export type Check = { label: string; ok: boolean; detail: string };
export type Step = { title: string; lines: string[]; checks: Check[] };
export type Report = { issuer: string; steps: Step[]; passed: boolean };

// Strict verification: pin issuer, type, nonce and audience, and require a key-binding JWT.
// Without keyBindingNonce and expectedKeyBindingAudience, verify() does not check key binding,
// and a credential presented with no KB-JWT at all is accepted.
async function verifyStrict(verifier: Verifier, presentation: string, request: Request, issuer: string) {
  const result = await verifier.verify(presentation, {
    expectedIssuer: issuer,
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

const newRequest = (aud = VERIFIER): Request => ({ nonce: crypto.randomUUID(), aud });

// issuerKeys defaults to a fresh key pair; the Worker passes its stable key from a secret.
export async function runScenario(issuer: string, issuerKeys?: KeyPair): Promise<Report> {
  issuerKeys ??= await generateKeyPair();
  const holderKeys = await generateKeyPair();
  const attackerKeys = await generateKeyPair();

  const issuerInstance = await createIssuer(issuerKeys);
  const holder = await createHolder(holderKeys);
  const attacker = await createHolder(attackerKeys);
  const verifier = await createVerifier(issuerKeys.publicKey);

  const steps: Step[] = [];
  const step = (title: string): Step => {
    const s: Step = { title, lines: [], checks: [] };
    steps.push(s);
    return s;
  };
  const expectRejected = (s: Step, label: string, err: string | null) =>
    s.checks.push({ label, ok: err !== null, detail: err ?? 'accepted' });

  // 1. Issue: a membership credential bound to the holder's public key.
  // Synthetic data only; no PHI.
  const s1 = step('1. Issue');
  const iat = nowSeconds();
  const credential = await issuerInstance.issue(
    {
      iss: issuer,
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
  s1.lines.push(`credential with ${credential.split('~').length - 2} selectively disclosable claims`);

  // 2. Request: the verifier sends a fresh nonce and its own identifier as audience.
  const s2 = step('2. Request');
  const request = newRequest();
  s2.lines.push(`nonce=${request.nonce} aud=${request.aud}`);

  // 3. Present: disclose only tier and organization, signed with the holder's key.
  const s3 = step('3. Present');
  const presentation = await holder.present(
    credential,
    { tier: true, organization: true },
    { kb: { payload: { iat: nowSeconds(), aud: request.aud, nonce: request.nonce } } },
  );
  s3.lines.push('disclosed: tier, organization');

  // 4. Verify (control): the honest presentation must pass and reveal only what was disclosed.
  const s4 = step('4. Verify (control)');
  const err = await rejectionOf(() => verifyStrict(verifier, presentation, request, issuer));
  s4.checks.push({ label: 'honest presentation accepted', ok: err === null, detail: err ?? '' });
  if (err === null) {
    const { payload } = await verifyStrict(verifier, presentation, request, issuer);
    s4.checks.push({
      label: 'only disclosed claims revealed',
      ok: payload.tier === 'gold' && payload.member_id === undefined,
      detail: '',
    });
  }

  const s5 = step('5. Attacks');

  // A1. Stolen credential, no key binding. Default verify() accepts it; verifyStrict must not.
  const stolen = await attacker.present(credential, { tier: true, organization: true });
  const lax = await rejectionOf(() => verifier.verify(stolen, { disableStatusVerification: true }));
  s5.lines.push(`default verify() on stolen credential: ${lax === null ? 'ACCEPTED' : 'rejected'}`);
  const a1 = await rejectionOf(() => verifyStrict(verifier, stolen, request, issuer));
  expectRejected(s5, 'A1 stolen credential without KB-JWT rejected', a1);

  // A2. Stolen credential with a KB-JWT signed by the attacker's own key.
  const forgedKb = await attacker.present(
    credential,
    { tier: true },
    { kb: { payload: { iat: nowSeconds(), aud: request.aud, nonce: request.nonce } } },
  );
  const a2 = await rejectionOf(() => verifyStrict(verifier, forgedKb, request, issuer));
  expectRejected(s5, 'A2 KB-JWT signed by wrong key rejected', a2);

  // A3. Replay: an earlier valid presentation reused against a new request (new nonce).
  const a3 = await rejectionOf(() => verifyStrict(verifier, presentation, newRequest(), issuer));
  expectRejected(s5, 'A3 replayed presentation rejected', a3);

  // A4. Forwarding: a presentation made for this verifier sent to a different one.
  const other = newRequest('https://other-verifier.example');
  const forwarded = await holder.present(
    credential,
    { tier: true },
    { kb: { payload: { iat: nowSeconds(), aud: request.aud, nonce: other.nonce } } },
  );
  const a4 = await rejectionOf(() => verifyStrict(verifier, forwarded, other, issuer));
  expectRejected(s5, 'A4 presentation for another audience rejected', a4);

  // A5. Tampered disclosure: change tier from gold to platinum after issuance.
  const parts = presentation.split('~');
  const idx = parts.findIndex((p, i) => {
    if (i === 0 || i === parts.length - 1 || !p) return false;
    return base64urlDecode(p).includes('"tier"');
  });
  const decoded = JSON.parse(base64urlDecode(parts[idx]));
  decoded[2] = 'platinum';
  parts[idx] = base64urlEncode(JSON.stringify(decoded));
  const a5 = await rejectionOf(() => verifyStrict(verifier, parts.join('~'), request, issuer));
  expectRejected(s5, 'A5 tampered disclosure rejected', a5);

  const passed = steps.every((s) => s.checks.every((c) => c.ok));
  return { issuer, steps, passed };
}
