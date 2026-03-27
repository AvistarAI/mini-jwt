import { describe, it, expect } from 'vitest';
import { generateKeyPair } from './keys.js';

describe('generateKeyPair()', () => {
  it('returns an object with publicKey and privateKey', async () => {
    const kp = await generateKeyPair();
    expect(kp).toHaveProperty('publicKey');
    expect(kp).toHaveProperty('privateKey');
  });

  it('publicKey has type "public" and algorithm ECDSA with namedCurve P-256', async () => {
    const kp = await generateKeyPair();
    expect(kp.publicKey.type).toBe('public');
    expect(kp.publicKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
  });

  it('privateKey has type "private" and algorithm ECDSA with namedCurve P-256', async () => {
    const kp = await generateKeyPair();
    expect(kp.privateKey.type).toBe('private');
    expect(kp.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
  });

  it('publicKey has verify usage', async () => {
    const kp = await generateKeyPair();
    expect(kp.publicKey.usages).toContain('verify');
  });

  it('privateKey has sign usage', async () => {
    const kp = await generateKeyPair();
    expect(kp.privateKey.usages).toContain('sign');
  });

  it('both keys are extractable', async () => {
    const kp = await generateKeyPair();
    expect(kp.publicKey.extractable).toBe(true);
    expect(kp.privateKey.extractable).toBe(true);
  });
});
