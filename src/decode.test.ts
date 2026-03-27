import { describe, it, expect, beforeAll } from 'vitest';
import { decode } from './decode.js';
import { sign } from './sign.js';
import { generateKeyPair } from './keys.js';
import { base64UrlEncode } from './base64url.js';
import type { JWTPayload, KeyPair } from './types.js';

describe('decode()', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('decodes a valid JWT and returns the original payload object', async () => {
    const inputPayload: JWTPayload = { sub: 'agent-007', iss: 'test-issuer', iat: 1700000000 };
    const token = await sign(inputPayload, keyPair.privateKey);
    const decoded = decode(token);
    expect(decoded.sub).toBe('agent-007');
    expect(decoded.iss).toBe('test-issuer');
    expect(decoded.iat).toBe(1700000000);
  });

  it('does not throw even when the signature is wrong (no sig verification)', () => {
    // Build a token with a bogus signature — decode should still succeed
    const headerB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', typ: 'JWT' })));
    const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ sub: 'no-sig' })));
    const fakeToken = `${headerB64}.${payloadB64}.invalidsignature`;
    expect(() => decode(fakeToken)).not.toThrow();
    const decoded = decode(fakeToken);
    expect(decoded.sub).toBe('no-sig');
  });

  it('throws when the token has fewer than three segments', () => {
    expect(() => decode('header.payload')).toThrow();
  });

  it('throws when the token has more than three segments', () => {
    expect(() => decode('a.b.c.d')).toThrow();
  });

  it('throws when the token has only one segment', () => {
    expect(() => decode('onlyone')).toThrow();
  });

  it('throws when the payload segment is invalid base64url', () => {
    // Use characters not in base64url alphabet after the first dot
    expect(() => decode('validheader.!!!invalid!!!.signature')).toThrow();
  });

  it('throws when the payload segment is valid base64url but not valid JSON', () => {
    // Encode a non-JSON string
    const notJson = base64UrlEncode(new TextEncoder().encode('this is not json'));
    expect(() => decode(`header.${notJson}.sig`)).toThrow();
  });

  it('throws when the payload segment decodes to a JSON array (not an object)', () => {
    const arrayPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify([1, 2, 3])));
    expect(() => decode(`header.${arrayPayload}.sig`)).toThrow();
  });

  it('decodes a token with all standard claims intact', async () => {
    const now = Math.floor(Date.now() / 1000);
    const inputPayload: JWTPayload = {
      iss: 'issuer',
      sub: 'subject',
      aud: 'audience',
      exp: now + 3600,
      nbf: now - 60,
      iat: now,
      jti: 'unique-id-123',
      customClaim: 'customValue',
    };
    const token = await sign(inputPayload, keyPair.privateKey);
    const decoded = decode(token);
    expect(decoded.iss).toBe('issuer');
    expect(decoded.sub).toBe('subject');
    expect(decoded.aud).toBe('audience');
    expect(decoded.exp).toBe(now + 3600);
    expect(decoded.nbf).toBe(now - 60);
    expect(decoded.jti).toBe('unique-id-123');
    expect(decoded.customClaim).toBe('customValue');
  });
});
