/**
 * Tests for the sign() function covering normal flow, iat injection,
 * iat preservation, and empty payload scenarios.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { sign } from '../src/sign.js';
import { generateKeyPair } from '../src/keys.js';
import { base64UrlDecode } from '../src/base64url.js';
import type { JWTHeader, JWTPayload, KeyPair } from '../src/types.js';

describe('sign() — normal flow', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('returns a string with exactly three dot-separated segments', async () => {
    const token = await sign({ sub: 'agent-1' }, keyPair.privateKey);
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
  });

  it('each segment contains only base64url characters', async () => {
    const token = await sign({ sub: 'agent-1' }, keyPair.privateKey);
    for (const part of token.split('.')) {
      expect(part).toMatch(/^[A-Za-z0-9\-_]+$/);
    }
  });

  it('first segment decodes to header with alg=ES256 and typ=JWT', async () => {
    const token = await sign({ sub: 'agent-1' }, keyPair.privateKey);
    const [headerSegment] = token.split('.');
    const headerBytes = base64UrlDecode(headerSegment as string);
    const header = JSON.parse(new TextDecoder().decode(headerBytes)) as JWTHeader;
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('JWT');
  });

  it('second segment decodes to the payload including all supplied claims', async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const input: JWTPayload = { sub: 'agent-007', iss: 'auth-service', exp, role: 'admin' };
    const token = await sign(input, keyPair.privateKey);
    const parts = token.split('.');
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;
    expect(decoded.sub).toBe('agent-007');
    expect(decoded.iss).toBe('auth-service');
    expect(decoded.exp).toBe(exp);
    expect(decoded['role']).toBe('admin');
  });

  it('produces a valid ECDSA P-256 signature over the signing input', async () => {
    const token = await sign({ sub: 'sig-check' }, keyPair.privateKey);
    const parts = token.split('.');
    const signingInput = `${parts[0]}.${parts[1]}`;
    const signatureBytes = base64UrlDecode(parts[2] as string);
    const isValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      keyPair.publicKey,
      signatureBytes,
      new TextEncoder().encode(signingInput),
    );
    expect(isValid).toBe(true);
  });
});

describe('sign() — iat injection', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('auto-sets iat to approximately the current Unix timestamp when not provided', async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await sign({ sub: 'time-test' }, keyPair.privateKey);
    const after = Math.floor(Date.now() / 1000);

    const parts = token.split('.');
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;

    expect(typeof decoded.iat).toBe('number');
    expect(decoded.iat as number).toBeGreaterThanOrEqual(before);
    expect(decoded.iat as number).toBeLessThanOrEqual(after);
  });

  it('iat is a whole-number Unix timestamp (no fractional seconds)', async () => {
    const token = await sign({ sub: 'whole-sec' }, keyPair.privateKey);
    const parts = token.split('.');
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;
    expect(Number.isInteger(decoded.iat)).toBe(true);
  });
});

describe('sign() — iat preservation', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('does not overwrite an existing iat claim', async () => {
    const existingIat = 1700000000;
    const token = await sign({ sub: 'preserve-iat', iat: existingIat }, keyPair.privateKey);
    const parts = token.split('.');
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;
    expect(decoded.iat).toBe(existingIat);
  });

  it('preserves iat=0 (falsy but defined) without replacing it', async () => {
    const token = await sign({ sub: 'zero-iat', iat: 0 }, keyPair.privateKey);
    const parts = token.split('.');
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;
    expect(decoded.iat).toBe(0);
  });
});

describe('sign() — empty payload', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('resolves with a three-segment JWT for an empty payload', async () => {
    const token = await sign({}, keyPair.privateKey);
    expect(token.split('.')).toHaveLength(3);
  });

  it('auto-injects iat as the only claim when payload is empty', async () => {
    const token = await sign({}, keyPair.privateKey);
    const parts = token.split('.');
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;
    const keys = Object.keys(decoded);
    expect(keys).toEqual(['iat']);
    expect(typeof decoded.iat).toBe('number');
  });
});
