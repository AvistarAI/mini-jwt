/**
 * Tests for the decode() function covering successful decode, expired token
 * decode, and malformed token errors.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { decode } from '../src/decode.js';
import { sign } from '../src/sign.js';
import { generateKeyPair } from '../src/keys.js';
import { base64UrlEncode } from '../src/base64url.js';
import type { JWTPayload, KeyPair } from '../src/types.js';

describe('decode() — successful decode', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('returns the original payload claims from a valid signed JWT', async () => {
    const inputPayload: JWTPayload = { sub: 'agent-007', iss: 'test-issuer', iat: 1700000000 };
    const token = await sign(inputPayload, keyPair.privateKey);
    const decoded = decode(token);
    expect(decoded.sub).toBe('agent-007');
    expect(decoded.iss).toBe('test-issuer');
    expect(decoded.iat).toBe(1700000000);
  });

  it('decodes all standard JWT claims from the payload', async () => {
    const now = Math.floor(Date.now() / 1000);
    const inputPayload: JWTPayload = {
      iss: 'issuer',
      sub: 'subject',
      aud: 'audience',
      exp: now + 3600,
      nbf: now - 60,
      iat: now,
      jti: 'unique-id-123',
    };
    const token = await sign(inputPayload, keyPair.privateKey);
    const decoded = decode(token);
    expect(decoded.iss).toBe('issuer');
    expect(decoded.sub).toBe('subject');
    expect(decoded.aud).toBe('audience');
    expect(decoded.exp).toBe(now + 3600);
    expect(decoded.nbf).toBe(now - 60);
    expect(decoded.jti).toBe('unique-id-123');
  });

  it('returns custom claims alongside standard claims', async () => {
    const now = Math.floor(Date.now() / 1000);
    const inputPayload: JWTPayload = {
      sub: 'agent-custom',
      iat: now,
      role: 'admin',
      permissions: ['read', 'write'],
    };
    const token = await sign(inputPayload, keyPair.privateKey);
    const decoded = decode(token);
    expect(decoded.sub).toBe('agent-custom');
    expect(decoded['role']).toBe('admin');
    expect(decoded['permissions']).toEqual(['read', 'write']);
  });

  it('does not perform signature verification — succeeds with a fake signature', () => {
    const headerB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', typ: 'JWT' })));
    const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ sub: 'no-sig-check' })));
    const fakeToken = `${headerB64}.${payloadB64}.invalidsignature`;
    expect(() => decode(fakeToken)).not.toThrow();
    const decoded = decode(fakeToken);
    expect(decoded.sub).toBe('no-sig-check');
  });
});

describe('decode() — expired token decode', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('decodes an expired token without throwing', async () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600;
    const expiredPayload: JWTPayload = {
      sub: 'agent-expired',
      iss: 'test-issuer',
      iat: pastExp - 60,
      exp: pastExp,
    };
    const token = await sign(expiredPayload, keyPair.privateKey);
    expect(() => decode(token)).not.toThrow();
  });

  it('returns the expired exp value unchanged', async () => {
    const pastExp = Math.floor(Date.now() / 1000) - 7200;
    const expiredPayload: JWTPayload = { sub: 'expired-sub', exp: pastExp };
    const token = await sign(expiredPayload, keyPair.privateKey);
    const decoded = decode(token);
    expect(decoded.exp).toBe(pastExp);
    expect(decoded.sub).toBe('expired-sub');
  });

  it('decodes a token that is not yet valid (nbf in future) without throwing', async () => {
    const futureNbf = Math.floor(Date.now() / 1000) + 3600;
    const payload: JWTPayload = { sub: 'future-agent', nbf: futureNbf };
    const token = await sign(payload, keyPair.privateKey);
    expect(() => decode(token)).not.toThrow();
    const decoded = decode(token);
    expect(decoded.nbf).toBe(futureNbf);
  });
});

describe('decode() — malformed token errors', () => {
  it('throws when given a token with only one segment (no dots)', () => {
    expect(() => decode('onlyone')).toThrow(/[Mm]alformed/);
  });

  it('throws when given a token with only two segments', () => {
    expect(() => decode('header.payload')).toThrow(/[Mm]alformed/);
  });

  it('throws when given a token with four segments', () => {
    expect(() => decode('a.b.c.d')).toThrow(/[Mm]alformed/);
  });

  it('throws when given an empty string', () => {
    expect(() => decode('')).toThrow();
  });

  it('throws when the payload segment is not valid JSON', () => {
    const notJson = base64UrlEncode(new TextEncoder().encode('this is not json'));
    expect(() => decode(`header.${notJson}.sig`)).toThrow(/[Mm]alformed/);
  });

  it('throws when the payload segment decodes to a JSON array (not an object)', () => {
    const arrayPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify([1, 2, 3])));
    expect(() => decode(`header.${arrayPayload}.sig`)).toThrow(/[Mm]alformed/);
  });

  it('error message mentions expected segment count when too few segments', () => {
    let errorMsg = '';
    try {
      decode('only.two');
    } catch (e) {
      errorMsg = (e as Error).message;
    }
    expect(errorMsg).toBeTruthy();
    expect(errorMsg.toLowerCase()).toContain('malformed');
  });

  it('error message mentions expected segment count when too many segments', () => {
    let errorMsg = '';
    try {
      decode('a.b.c.d.e');
    } catch (e) {
      errorMsg = (e as Error).message;
    }
    expect(errorMsg).toBeTruthy();
    expect(errorMsg.toLowerCase()).toContain('malformed');
  });
});
