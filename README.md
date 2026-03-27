# mini-jwt

A minimal JWT (JSON Web Token) library in TypeScript. Zero runtime dependencies — all cryptographic operations use the Web Crypto API.

**This library was built entirely by an autonomous AI coding harness** — no human wrote a single line of implementation code. See [How It Was Built](#how-it-was-built) below.

## Features

- ES256 (ECDSA P-256 + SHA-256) signing and verification
- Zero runtime dependencies (Web Crypto API only)
- Works in Node.js 18+, Deno, Cloudflare Workers, and browsers
- Full TypeScript types with strict mode
- Comprehensive edge case handling (expired tokens, tampered payloads, audience mismatch, malformed input)

## Installation

```bash
npm install mini-jwt
```

## Quick Start

```typescript
import { generateKeyPair, sign, verify, decode } from 'mini-jwt';

// Generate a signing key pair
const keys = await generateKeyPair();

// Sign a token
const token = await sign({
  iss: 'https://idp.acme.com',
  sub: 'agent:code-review-bot',
  aud: 'https://api.github.com',
  exp: Math.floor(Date.now() / 1000) + 3600,
  iat: Math.floor(Date.now() / 1000),
  agent_name: 'Code Review Bot',
  capabilities: ['read:repos', 'write:comments'],
}, keys.privateKey);

// Verify a token
const result = await verify(token, keys.publicKey);
if (result.valid) {
  console.log('Agent:', result.payload.sub);
  console.log('Capabilities:', result.payload.capabilities);
} else {
  console.error('Verification failed:', result.errors);
}

// Decode without verification (for logging/debugging)
const payload = decode(token);
console.log(payload.iss, payload.sub);
```

## API

### `generateKeyPair(): Promise<KeyPair>`

Generate an ES256 (ECDSA P-256) key pair for signing and verifying tokens.

### `sign(payload: JWTPayload, privateKey: CryptoKey): Promise<string>`

Create and sign a JWT. Returns the compact JWS string (`header.payload.signature`).

### `verify(token: string, publicKey: CryptoKey, options?: { audience?: string }): Promise<VerifyResult>`

Verify a JWT's signature and validate claims. Returns:
```typescript
{
  valid: boolean;
  payload: JWTPayload;    // decoded payload (even if invalid)
  errors: string[];       // empty if valid
}
```

Validation checks:
- Signature validity (ECDSA P-256)
- `exp` — rejects expired tokens
- `nbf` — rejects tokens not yet valid
- `aud` — audience enforcement (when `options.audience` provided)
- Structural integrity (3 segments, valid base64url, valid JSON)

### `decode(token: string): JWTPayload`

Decode a JWT without verification. For logging and debugging. Throws on malformed tokens.

### `base64UrlEncode(data: Uint8Array): string` / `base64UrlDecode(str: string): Uint8Array`

Low-level base64url encoding/decoding utilities.

## Types

```typescript
interface JWTHeader {
  alg: 'ES256';
  typ: 'JWT';
  kid?: string;
}

interface JWTPayload {
  iss?: string;          // Issuer
  sub?: string;          // Subject
  aud?: string | string[]; // Audience
  exp?: number;          // Expiration (Unix timestamp)
  iat?: number;          // Issued at
  nbf?: number;          // Not before
  jti?: string;          // JWT ID
  [key: string]: unknown; // Custom claims
}

interface VerifyResult {
  valid: boolean;
  payload: JWTPayload;
  errors: string[];
}

interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}
```

## Test Coverage

```
 Test Files  8 passed (8)
      Tests  76 passed (76)

 % Coverage report from v8
--------------|---------|----------|---------|---------|
File          | % Stmts | % Branch | % Funcs | % Lines |
--------------|---------|----------|---------|---------|
All files     |   96.15 |    96.07 |     100 |   96.15 |
 base64url.ts |     100 |      100 |     100 |     100 |
 decode.ts    |     100 |      100 |     100 |     100 |
 keys.ts      |     100 |      100 |     100 |     100 |
 sign.ts      |     100 |      100 |     100 |     100 |
 verify.ts    |   92.47 |    93.54 |     100 |   92.47 |
```

---

## How It Was Built

This library was generated entirely by an autonomous coding harness — a Python orchestrator that uses Claude (via the `claude-agent-sdk`) to plan, implement, test, and review code without human intervention.

### The Harness

The harness implements a planner/generator/evaluator agent loop inspired by [Anthropic's research on long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents):

1. **Planner** — read the spec, decomposed it into 38 features with BDD scenarios
2. **Generator** — implemented one feature per session, wrote tests, committed after each
3. **Hard Validators** — TypeScript type checking, ESLint, build, and test suite must all pass before a feature is accepted (the agent cannot skip these)
4. **Evaluator** — adversarial code review by a separate Claude session that scores on spec compliance, code quality, security, and usability (minimum 7.0/10 to pass)

Setup and simple features skip the evaluator (validators are sufficient), while crypto and security-critical features get full adversarial review.

### Build Stats

| Metric | Value |
|---|---|
| Total features | 38 |
| Features passing | 38/38 (100%) |
| Total time | ~70 minutes |
| Total cost | $9.27 (Claude Sonnet 4.6 on Max) |
| Test count | 76 tests |
| Test coverage | 96% statements, 100% functions |
| Runtime dependencies | 0 |
| Human code written | 0 lines |

### What This Proves

- Autonomous coding agents can produce library-quality code with real test coverage
- The adversarial evaluator catches issues that the generator misses (security-critical signature comparisons, edge cases)
- Hard validation gates (linter, type checker, tests) prevent the agent from declaring victory on broken code
- Feature complexity tiers (setup/simple/moderate/complex) dramatically reduce build time by skipping evaluator where validators suffice

### Source

The harness source code is at [shawnpetros/long-running-harness](https://github.com/shawnpetros/long-running-harness).

## License

MIT
