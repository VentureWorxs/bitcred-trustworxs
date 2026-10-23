# bitcred-trustworxs

A small SD-JWT verifiable credential (SD-JWT VC) demo in TypeScript, live at **https://bitcred.trustworxs.com**. An issuer signs a credential bound to the holder's key. The holder shows only some of its claims to a verifier. Then the demo runs attacks that a correctly set-up verifier must reject.

## Run

Requires Node 20+.

```sh
npm install
npm run demo        # issue, request, present, verify, attacks
npm run typecheck
```

`npm run demo` exits non-zero if any check fails.

## Cloudflare

The same scenario runs as a Cloudflare Worker (`bitcred-trustworxs` on the VENTUREWORXS account), served at `bitcred.trustworxs.com` through a Worker custom domain in [wrangler.toml](wrangler.toml). Wrangler creates the DNS record and certificate, so there is no Pulumi stack.

| Path | What it returns |
|---|---|
| `/` | Page that runs the demo and shows the results ([html/index.html](html/index.html)) |
| `/api/run` | One run of the scenario as JSON |
| `/.well-known/jwt-vc-issuer` | Issuer metadata with the issuer's public key (JWKS) |

The issuer's private key is the `ISSUER_JWK` Worker secret, so it stays the same across runs. To set it up or rotate it:

```sh
npm run keygen | npx wrangler secret put ISSUER_JWK
npm run deploy
```

For local development, put `ISSUER_JWK='<jwk json>'` in `.dev.vars` (gitignored) and run `npm run dev`.

## What it does

| Step | What happens |
|---|---|
| Issue | Issuer signs a membership credential (synthetic data, no PHI) with five selectively disclosable claims, bound to the holder's key via `cnf.jwk`. |
| Request | Verifier sends a fresh nonce and its own identifier as audience. |
| Present | Holder discloses `tier` and `organization` only, and signs a key-binding JWT (KB-JWT) over the nonce and audience. |
| Verify (control) | The honest presentation is accepted and undisclosed claims stay hidden. |

Attacks, all of which must be rejected:

| Test | Attack |
|---|---|
| A1 | Stolen credential presented with no KB-JWT |
| A2 | Stolen credential with a KB-JWT signed by the attacker's key |
| A3 | Replay of a valid presentation against a new nonce |
| A4 | Presentation made for one verifier forwarded to another |
| A5 | Disclosure edited after issuance (`tier` changed to `platinum`) |

## Key finding: key binding is opt-in

With `@sd-jwt/sd-jwt-vc` 0.23, `verify()` does not check key binding unless you pass `keyBindingNonce` and `expectedKeyBindingAudience`. A credential presented without any KB-JWT is accepted, so whoever holds a copy of the credential can use it. The demo prints this as `default verify() on stolen credential: ACCEPTED`.

`verifyStrict` in [src/scenario.ts](src/scenario.ts) passes the nonce, audience, expected issuer and `vct`, and also checks that `kb` is present in the result.

## Files

- [src/common.ts](src/common.ts): keys and issuer, holder and verifier instances (ES256, WebCrypto via `@sd-jwt/crypto-browser`, so it runs in Node and on Workers). The verifier checks the KB-JWT against the holder key in the credential's `cnf.jwk`.
- [src/scenario.ts](src/scenario.ts): the walkthrough and attack tests, returned as a report.
- [src/demo.ts](src/demo.ts): CLI that prints the report.
- [src/worker.ts](src/worker.ts): the Worker routes.
- [src/keygen.ts](src/keygen.ts): prints a new issuer private key for the secret.

## Simplifications

- Everything runs in memory. There is no OID4VCI or OID4VP over HTTP yet.
- The verifier gets the issuer's public key directly. The Worker publishes it at `/.well-known/jwt-vc-issuer`, but the verifier does not fetch it from there yet.
- Each run generates new holder and attacker keys, and the in-page verifier is the same Worker as the issuer.
- No revocation. Status checks are disabled until Token Status List is added.
- The verifier does not keep track of used nonces. Replays are caught only because each request has a new nonce.
