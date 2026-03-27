/**
 * Key generation utilities for the Agent Identity Token (AIT) standard.
 * Uses the Web Crypto API to generate ES256 (ECDSA P-256) key pairs.
 * @module keys
 */

import type { KeyPair } from './types.js';

/** ECDSA P-256 algorithm parameters used for key generation. */
const ECDSA_PARAMS: EcKeyGenParams = {
  name: 'ECDSA',
  namedCurve: 'P-256',
};

/**
 * Generates an ECDSA P-256 key pair suitable for signing and verifying AIT tokens.
 *
 * Both keys are marked extractable so they can be exported (e.g. to JWK format)
 * if the caller needs to persist or share them.
 *
 * @returns A {@link KeyPair} whose `privateKey` can be passed to `sign()` and
 *   whose `publicKey` can be passed to `verify()`.
 *
 * @example
 * ```ts
 * const { publicKey, privateKey } = await generateKeyPair();
 * const token = await sign({ sub: 'agent-1' }, privateKey);
 * const result = await verify(token, publicKey);
 * ```
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    ECDSA_PARAMS,
    /* extractable */ true,
    /* usages */ ['sign', 'verify'],
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}
