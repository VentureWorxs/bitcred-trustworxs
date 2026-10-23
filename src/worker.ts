// Cloudflare Worker: serves html/ as static assets, runs the scenario on demand,
// and publishes the issuer's public key as SD-JWT VC issuer metadata.
import { keyPairFromPrivateJwk, type KeyPair } from './common.js';
import { runScenario } from './scenario.js';

interface Env {
  ISSUER_URL: string;
  ISSUER_JWK: string; // secret: private EC P-256 JWK as JSON (see README)
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

function issuerKeys(env: Env): KeyPair {
  if (!env.ISSUER_JWK) throw new Error('ISSUER_JWK secret is not set');
  return keyPairFromPrivateJwk(JSON.parse(env.ISSUER_JWK));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (request.method !== 'GET') return json({ error: 'method not allowed' }, 405);

    try {
      if (pathname === '/api/run') {
        return json(await runScenario(env.ISSUER_URL, issuerKeys(env)));
      }
      // Issuer metadata per SD-JWT VC: verifiers can fetch the key for iss from here.
      if (pathname === '/.well-known/jwt-vc-issuer') {
        return json({ issuer: env.ISSUER_URL, jwks: { keys: [issuerKeys(env).publicKey] } });
      }
    } catch (e) {
      console.error(e);
      return json({ error: 'internal error' }, 500);
    }
    return json({ error: 'not found' }, 404);
  },
};
