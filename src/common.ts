// Shared setup for the SD-JWT VC demo: keys and the issuer, holder and verifier
// instances. Uses WebCrypto only, so the same code runs in Node and on Cloudflare Workers.
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-browser';

export type KeyPair = Awaited<ReturnType<typeof ES256.generateKeyPair>>;
export type Jwk = KeyPair['publicKey'];

export const VERIFIER = 'https://verifier.trustworxs.example';
export const VCT = 'https://trustworxs.example/credentials/membership';

export const generateKeyPair = (): Promise<KeyPair> => ES256.generateKeyPair();

// Rebuilds a key pair from a private EC JWK by dropping the private part (d).
export function keyPairFromPrivateJwk(privateKey: Jwk): KeyPair {
  const { d: _d, key_ops: _ops, ...publicKey } = privateKey;
  return { privateKey, publicKey };
}

// Settings shared by every party: hash and salt functions for disclosures.
const base = {
  hasher: digest,
  hashAlg: 'sha-256' as const,
  saltGenerator: generateSalt,
};

export async function createIssuer(issuerKeys: KeyPair) {
  return new SDJwtVcInstance({
    ...base,
    signer: await ES256.getSigner(issuerKeys.privateKey),
    signAlg: ES256.alg,
  });
}

// The holder signs the key-binding JWT with the key the credential is bound to (cnf.jwk).
export async function createHolder(holderKeys: KeyPair) {
  return new SDJwtVcInstance({
    ...base,
    kbSigner: await ES256.getSigner(holderKeys.privateKey),
    kbSignAlg: ES256.alg,
  });
}

// The verifier trusts one issuer key (passed in memory for now; see README for did:web/JWKS).
// The key-binding verifier checks the KB-JWT against the holder key inside the credential,
// so a KB-JWT signed with any other key fails.
export async function createVerifier(issuerPublicKey: Jwk) {
  return new SDJwtVcInstance({
    ...base,
    verifier: await ES256.getVerifier(issuerPublicKey),
    kbVerifier: async (data, sig, payload) => {
      const cnf = payload.cnf as { jwk?: Jwk } | undefined;
      if (!cnf?.jwk) throw new Error('credential has no cnf.jwk holder key');
      const verify = await ES256.getVerifier(cnf.jwk);
      return verify(data, sig);
    },
  });
}

export const nowSeconds = () => Math.floor(Date.now() / 1000);

export const base64urlDecode = (s: string) =>
  new TextDecoder().decode(
    Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
  );

export const base64urlEncode = (s: string) =>
  btoa(String.fromCharCode(...new TextEncoder().encode(s)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
