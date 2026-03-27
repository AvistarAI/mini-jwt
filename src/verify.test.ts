import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from './verify.js';
import { sign } from './sign.js';
import { generateKeyPair } from './keys.js';
import { base64UrlEncode } from './base64url.js';
import type { JWTPayload, KeyPair } from './types.js';

describe('verify()', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  // ── Happy path ─────────────────────────────────────────────────────────────

  it('returns valid=true and the payload for a correctly signed token', async () => {
    const inputPayload: JWTPayload = { sub: 'agent-1', iat: 1700000000 };
    const token = await sign(inputPayload, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.payload?.sub).toBe('agent-1');
    expect(result.payload?.iat).toBe(1700000000);
  });

  it('returns valid=true and errors is an empty array (not undefined)', async () => {
    const token = await sign({ sub: 'array-check' }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(Array.isArray(result.errors)).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('returns valid=true for a token with all standard claims', async () => {
    const now = Math.floor(Date.now() / 1000);
    const inputPayload: JWTPayload = {
      iss: 'issuer',
      sub: 'subject',
      aud: 'audience',
      exp: now + 3600,
      nbf: now - 60,
      iat: now,
      jti: 'unique-id-abc',
    };
    const token = await sign(inputPayload, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(true);
    expect(result.payload?.iss).toBe('issuer');
    expect(result.payload?.sub).toBe('subject');
    expect(result.payload?.aud).toBe('audience');
    expect(result.payload?.jti).toBe('unique-id-abc');
  });

  it('returns valid=true for a token with an empty payload (auto-iat only)', async () => {
    const token = await sign({}, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(typeof result.payload?.iat).toBe('number');
  });

  // ── Signature tampering ────────────────────────────────────────────────────

  it('returns valid=false when the signature is replaced with a random string', async () => {
    const token = await sign({ sub: 'tamper-test' }, keyPair.privateKey);
    const parts = token.split('.');
    const tampered = `${parts[0]}.${parts[1]}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    const result = await verify(tampered, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/signature/i);
  });

  it('returns valid=false when the payload is tampered (changing a claim byte)', async () => {
    const token = await sign({ sub: 'original' }, keyPair.privateKey);
    const parts = token.split('.');
    // Replace the payload with an encoded different claim
    const fakePayload = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify({ sub: 'tampered' })),
    );
    const tampered = `${parts[0]}.${fakePayload}.${parts[2]}`;
    const result = await verify(tampered, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/signature/i);
  });

  it('returns valid=false when the header is tampered', async () => {
    const token = await sign({ sub: 'header-tamper' }, keyPair.privateKey);
    const parts = token.split('.');
    // Replace the header with a slightly different one
    const fakeHeader = base64UrlEncode(
      new TextEncoder().encode(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'injected' })),
    );
    const tampered = `${fakeHeader}.${parts[1]}.${parts[2]}`;
    const result = await verify(tampered, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/signature/i);
  });

  it('returns valid=false when verified against a different key pair', async () => {
    const otherKeyPair = await generateKeyPair();
    const token = await sign({ sub: 'wrong-key' }, keyPair.privateKey);
    const result = await verify(token, otherKeyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/signature/i);
  });

  // ── Claims validation ──────────────────────────────────────────────────────

  it('returns valid=false with an expired-token error when exp is 60 seconds in the past', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ sub: 'expired-agent', exp: now - 60 }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors.some((e) => /expired/i.test(e))).toBe(true);
  });

  it('returns valid=true when exp is 3600 seconds in the future', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ sub: 'future-agent', exp: now + 3600 }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('returns valid=false with a not-yet-valid error when nbf is 60 seconds in the future', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ sub: 'future-nbf-agent', nbf: now + 60 }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors.some((e) => /not yet valid/i.test(e))).toBe(true);
  });

  // ── Audience validation ────────────────────────────────────────────────────

  it('F020: returns valid=true and errors is empty when aud matches options.audience (single string)', async () => {
    const token = await sign({ sub: 'agent-x', aud: 'my-api' }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey, { audience: 'my-api' });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('F021: returns valid=true and errors is empty when aud is an array containing options.audience', async () => {
    const token = await sign({ sub: 'agent-y', aud: ['my-api', 'other-service'] }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey, { audience: 'my-api' });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('F019: returns valid=false with audience mismatch error when aud does not match options.audience', async () => {
    const token = await sign({ sub: 'agent-a', aud: 'service-a' }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey, { audience: 'service-b' });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors.some((e) => /audience/i.test(e))).toBe(true);
  });

  it('F018: returns valid=true and errors is empty when nbf is 60 seconds in the past', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign({ sub: 'past-nbf-agent', nbf: now - 60 }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  // ── Structural / malformed tokens ─────────────────────────────────────────

  it('returns valid=false when the token has only two segments', async () => {
    const result = await verify('header.payload', keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/malformed/i);
  });

  it('returns valid=false when the token has four segments', async () => {
    const result = await verify('a.b.c.d', keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/malformed/i);
  });

  it('returns valid=false when the token is an empty string', async () => {
    const result = await verify('', keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns valid=false when the payload segment is invalid base64url', async () => {
    const token = await sign({ sub: 'base64-test' }, keyPair.privateKey);
    const parts = token.split('.');
    const tampered = `${parts[0]}.!!!invalid!!!!!.${parts[2]}`;
    const result = await verify(tampered, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns valid=false when the payload is valid base64url but not valid JSON', async () => {
    const token = await sign({ sub: 'json-test' }, keyPair.privateKey);
    const parts = token.split('.');
    const notJson = base64UrlEncode(new TextEncoder().encode('not json at all'));
    const tampered = `${parts[0]}.${notJson}.${parts[2]}`;
    const result = await verify(tampered, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns valid=false and payload is undefined when signature is invalid', async () => {
    const token = await sign({ sub: 'no-payload-on-fail' }, keyPair.privateKey);
    const parts = token.split('.');
    const tampered = `${parts[0]}.${parts[1]}.invalidsignatureXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`;
    const result = await verify(tampered, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.payload).toBeUndefined();
  });
});
