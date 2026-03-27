/**
 * Edge-case tests covering: wrong key, multi-error accumulation,
 * array audience, missing signature, and full-claim round-trip.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { verify } from '../src/verify.js';
import { sign } from '../src/sign.js';
import { generateKeyPair } from '../src/keys.js';
import type { JWTPayload, KeyPair } from '../src/types.js';

describe('edge cases — wrong key', () => {
  let keyPairA: KeyPair;
  let keyPairB: KeyPair;

  beforeAll(async () => {
    [keyPairA, keyPairB] = await Promise.all([generateKeyPair(), generateKeyPair()]);
  });

  it('returns valid=false when a token signed with key A is verified with key B', async () => {
    const token = await sign({ sub: 'agent-key-a' }, keyPairA.privateKey);
    const result = await verify(token, keyPairB.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors.some((e) => /signature/i.test(e))).toBe(true);
    expect(result.payload).toBeUndefined();
  });

  it('returns valid=true when the correct key is used after attempting the wrong one', async () => {
    const token = await sign({ sub: 'check-correct-key' }, keyPairA.privateKey);
    const wrongResult = await verify(token, keyPairB.publicKey);
    expect(wrongResult.valid).toBe(false);

    const correctResult = await verify(token, keyPairA.publicKey);
    expect(correctResult.valid).toBe(true);
    expect(correctResult.errors).toHaveLength(0);
    expect(correctResult.payload?.sub).toBe('check-correct-key');
  });
});

describe('edge cases — multi-error accumulation', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('accumulates both exp and nbf errors when both claims fail simultaneously', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign(
      {
        sub: 'multi-error-agent',
        exp: now - 60, // already expired
        nbf: now + 60, // not yet valid
      },
      keyPair.privateKey,
    );
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(2);
    expect(result.errors.some((e) => /expired/i.test(e))).toBe(true);
    expect(result.errors.some((e) => /not yet valid/i.test(e))).toBe(true);
  });

  it('accumulates exp error and audience mismatch error simultaneously', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign(
      {
        sub: 'multi-aud-exp',
        exp: now - 120,
        aud: 'service-a',
      },
      keyPair.privateKey,
    );
    const result = await verify(token, keyPair.publicKey, { audience: 'service-b' });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(2);
    expect(result.errors.some((e) => /expired/i.test(e))).toBe(true);
    expect(result.errors.some((e) => /audience/i.test(e))).toBe(true);
  });
});

describe('edge cases — array audience', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('returns valid=true when aud is an array and options.audience matches one entry', async () => {
    const token = await sign(
      { sub: 'multi-aud-agent', aud: ['api-v1', 'api-v2', 'admin'] },
      keyPair.privateKey,
    );
    const result = await verify(token, keyPair.publicKey, { audience: 'api-v2' });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('returns valid=false when aud is an array and options.audience does not match any entry', async () => {
    const token = await sign(
      { sub: 'multi-aud-agent', aud: ['api-v1', 'api-v2'] },
      keyPair.privateKey,
    );
    const result = await verify(token, keyPair.publicKey, { audience: 'api-v3' });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => /audience/i.test(e))).toBe(true);
  });

  it('returns valid=true when aud is an empty array and no options.audience is provided', async () => {
    const token = await sign({ sub: 'empty-aud-agent', aud: [] }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(true);
  });

  it('round-trips aud as an array through sign and verify payload', async () => {
    const audiences = ['svc-a', 'svc-b', 'svc-c'];
    const token = await sign({ sub: 'array-aud-rt', aud: audiences }, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey, { audience: 'svc-b' });
    expect(result.valid).toBe(true);
    expect(result.payload?.aud).toEqual(audiences);
  });
});

describe('edge cases — missing or empty signature', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('returns valid=false when the signature segment is an empty string', async () => {
    const token = await sign({ sub: 'no-sig' }, keyPair.privateKey);
    const parts = token.split('.');
    const noSig = `${parts[0]}.${parts[1]}.`;
    const result = await verify(noSig, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns valid=false (not a throw) when only two segments are present', async () => {
    const token = await sign({ sub: 'two-seg' }, keyPair.privateKey);
    const parts = token.split('.');
    const twoSeg = `${parts[0]}.${parts[1]}`;
    const result = await verify(twoSeg, keyPair.publicKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('returns valid=false when the signature is replaced with a single non-base64url character', async () => {
    const token = await sign({ sub: 'bad-sig' }, keyPair.privateKey);
    const parts = token.split('.');
    const badSig = `${parts[0]}.${parts[1]}.!`;
    const result = await verify(badSig, keyPair.publicKey);
    expect(result.valid).toBe(false);
  });
});

describe('edge cases — full-claim round-trip', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await generateKeyPair();
  });

  it('preserves all standard claims through a sign → verify round-trip', async () => {
    const now = Math.floor(Date.now() / 1000);
    const inputPayload: JWTPayload = {
      iss: 'https://issuer.example.com',
      sub: 'user-round-trip-123',
      aud: 'round-trip-api',
      exp: now + 3600,
      nbf: now - 10,
      iat: now,
      jti: 'unique-jwt-id-xyz',
    };

    const token = await sign(inputPayload, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey, { audience: 'round-trip-api' });

    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.payload?.iss).toBe(inputPayload.iss);
    expect(result.payload?.sub).toBe(inputPayload.sub);
    expect(result.payload?.aud).toBe(inputPayload.aud);
    expect(result.payload?.exp).toBe(inputPayload.exp);
    expect(result.payload?.nbf).toBe(inputPayload.nbf);
    expect(result.payload?.iat).toBe(inputPayload.iat);
    expect(result.payload?.jti).toBe(inputPayload.jti);
  });

  it('preserves custom application claims through a sign → verify round-trip', async () => {
    const inputPayload: JWTPayload = {
      sub: 'agent-custom-claims',
      role: 'admin',
      permissions: ['read', 'write', 'delete'],
      metadata: { region: 'us-east-1', tier: 'premium' },
    };

    const token = await sign(inputPayload, keyPair.privateKey);
    const result = await verify(token, keyPair.publicKey);

    expect(result.valid).toBe(true);
    expect(result.payload?.role).toBe('admin');
    expect(result.payload?.permissions).toEqual(['read', 'write', 'delete']);
    expect(result.payload?.metadata).toEqual({ region: 'us-east-1', tier: 'premium' });
  });

  it('auto-injects iat when not provided and preserves it in the verified payload', async () => {
    const before = Math.floor(Date.now() / 1000);
    const token = await sign({ sub: 'iat-inject-test' }, keyPair.privateKey);
    const after = Math.floor(Date.now() / 1000);

    const result = await verify(token, keyPair.publicKey);
    expect(result.valid).toBe(true);
    expect(typeof result.payload?.iat).toBe('number');
    expect(result.payload!.iat).toBeGreaterThanOrEqual(before);
    expect(result.payload!.iat).toBeLessThanOrEqual(after);
  });
});
