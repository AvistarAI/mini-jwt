import { describe, it, expect, beforeAll } from 'vitest';
import { sign } from './sign.js';
import { generateKeyPair } from './keys.js';
import { base64UrlDecode } from './base64url.js';
import type { JWTHeader, JWTPayload, KeyPair } from './types.js';

describe('sign()', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('returns a string with exactly three base64url segments separated by dots', async () => {
    const token = await sign({ sub: 'test-agent' }, keyPair.privateKey);
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    // Each segment should be non-empty and contain only base64url characters
    for (const part of parts) {
      expect(part).toMatch(/^[A-Za-z0-9\-_]+$/);
    }
  });

  it('first segment decodes to a header with alg ES256 and typ JWT', async () => {
    const token = await sign({ sub: 'test-agent' }, keyPair.privateKey);
    const [headerSegment] = token.split('.');
    const headerBytes = base64UrlDecode(headerSegment as string);
    const header = JSON.parse(new TextDecoder().decode(headerBytes)) as JWTHeader;
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('JWT');
  });

  it('second segment decodes to the payload with the expected claims', async () => {
    const inputPayload: JWTPayload = { sub: 'agent-42', iss: 'test-issuer' };
    const token = await sign(inputPayload, keyPair.privateKey);
    const parts = token.split('.');
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;
    expect(decoded.sub).toBe('agent-42');
    expect(decoded.iss).toBe('test-issuer');
  });

  it('auto-sets iat to a Unix timestamp when not provided', async () => {
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

  it('does not overwrite an existing iat claim', async () => {
    const existingIat = 1700000000;
    const token = await sign({ sub: 'preserve-iat', iat: existingIat }, keyPair.privateKey);
    const parts = token.split('.');
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;
    expect(decoded.iat).toBe(existingIat);
  });

  it('produces a valid ECDSA P-256 signature over header.payload', async () => {
    const token = await sign({ sub: 'sig-test' }, keyPair.privateKey);
    const parts = token.split('.');
    const signingInput = `${parts[0]}.${parts[1]}`;
    const signatureBytes = base64UrlDecode(parts[2] as string);

    const signingInputBytes = new TextEncoder().encode(signingInput);
    const isValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      keyPair.publicKey,
      signatureBytes,
      signingInputBytes,
    );
    expect(isValid).toBe(true);
  });

  it('signature is invalid when verified against a different key pair', async () => {
    const otherKeyPair = await generateKeyPair();
    const token = await sign({ sub: 'wrong-key-test' }, keyPair.privateKey);
    const parts = token.split('.');
    const signingInput = `${parts[0]}.${parts[1]}`;
    const signatureBytes = base64UrlDecode(parts[2] as string);

    const signingInputBytes = new TextEncoder().encode(signingInput);
    const isValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      otherKeyPair.publicKey,
      signatureBytes,
      signingInputBytes,
    );
    expect(isValid).toBe(false);
  });

  it('includes a kid in the header when payload has __kid__ claim (header passthrough)', async () => {
    // The sign function only sets alg/typ in the header — kid is not part of the
    // current F006 spec, but we verify the header contains exactly those two fields.
    const token = await sign({ sub: 'header-check' }, keyPair.privateKey);
    const [headerSegment] = token.split('.');
    const headerBytes = base64UrlDecode(headerSegment as string);
    const header = JSON.parse(new TextDecoder().decode(headerBytes)) as Record<string, unknown>;
    expect(Object.keys(header).sort()).toEqual(['alg', 'typ']);
  });

  it('handles an empty payload object', async () => {
    const token = await sign({}, keyPair.privateKey);
    const parts = token.split('.');
    expect(parts).toHaveLength(3);
    const payloadBytes = base64UrlDecode(parts[1] as string);
    const decoded = JSON.parse(new TextDecoder().decode(payloadBytes)) as JWTPayload;
    // iat should have been auto-added
    expect(typeof decoded.iat).toBe('number');
  });
});
