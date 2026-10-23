# bitcred-trustworxs

A small SD-JWT verifiable credential (SD-JWT VC) demo in TypeScript. An issuer signs a credential bound to the holder's key. The holder shows only some of its claims to a verifier. Then the demo runs attacks that a correctly set-up verifier must reject.

## Run

Requires Node 20+.

```sh
npm install
npm run demo        # issue, request, present, verify, attacks
npm run typecheck
```

`npm run demo` exits non-zero if any check fails.

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

`verifyStrict` in [src/demo.ts](src/demo.ts) passes the nonce, audience, expected issuer and `vct`, and also checks that `kb` is present in the result.

## Files

- [src/common.ts](src/common.ts): keys and issuer, holder and verifier instances (ES256). The verifier checks the KB-JWT against the holder key in the credential's `cnf.jwk`.
- [src/demo.ts](src/demo.ts): the walkthrough and attack tests.

## Simplifications

- Everything runs in memory. There is no OID4VCI or OID4VP over HTTP yet.
- The verifier gets the issuer's public key directly, not from `did:web` or JWKS.
- No revocation. Status checks are disabled until Token Status List is added.
- The verifier does not keep track of used nonces. Replays are caught only because each request has a new nonce.
