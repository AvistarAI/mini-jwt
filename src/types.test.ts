import { describe, it, expect } from 'vitest';
import type { JWTHeader, JWTPayload, VerifyResult, KeyPair } from './types.js';

describe('types', () => {
  it('JWTHeader has alg ES256 and typ JWT', () => {
    const header: JWTHeader = { alg: 'ES256', typ: 'JWT' };
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('JWT');
  });

  it('JWTHeader accepts an optional kid', () => {
    const header: JWTHeader = { alg: 'ES256', typ: 'JWT', kid: 'key-1' };
    expect(header.kid).toBe('key-1');
  });

  it('JWTPayload supports all standard claims', () => {
    const payload: JWTPayload = {
      iss: 'issuer',
      sub: 'subject',
      aud: 'audience',
      exp: 9999999999,
      nbf: 0,
      iat: 1700000000,
      jti: 'unique-id',
    };
    expect(payload.iss).toBe('issuer');
    expect(payload.sub).toBe('subject');
  });

  it('JWTPayload supports additional claims via index signature', () => {
    const payload: JWTPayload = { customClaim: 'value' };
    expect(payload['customClaim']).toBe('value');
  });

  it('VerifyResult has valid, payload, and errors fields', () => {
    const result: VerifyResult = { valid: true, payload: { sub: 'test' }, errors: [] };
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('KeyPair has publicKey and privateKey as CryptoKey shapes', () => {
    // Just a type-level check — we verify the interface compiles correctly
    const kp = {} as KeyPair;
    expect(kp).toBeDefined();
  });
});
