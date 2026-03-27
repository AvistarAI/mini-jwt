/**
 * JWT signing utilities for the Agent Identity Token (AIT) standard.
 * Uses the Web Crypto API to produce compact ES256-signed JWT strings.
 * @module sign
 */

import { base64UrlEncode } from './base64url.js';
import type { JWTHeader, JWTPayload } from './types.js';

/** Text encoder singleton — reused to avoid repeated allocations. */
const encoder = new TextEncoder();

/** ECDSA signing algorithm parameters (P-256 with SHA-256). */
const SIGN_ALGORITHM: EcdsaParams = {
  name: 'ECDSA',
  hash: { name: 'SHA-256' },
};

/**
 * Signs a JWT payload with the given ECDSA P-256 private key and returns a
 * compact JWT string in the format `header.payload.signature`.
 *
 * The header is always `{ alg: 'ES256', typ: 'JWT' }`. If the payload does not
 * already include an `iat` claim, the current time (in whole seconds) is added
 * automatically.
 *
 * The signature covers exactly the ASCII bytes of the string
 * `base64url(header) + '.' + base64url(payload)` using ECDSA over P-256 with
 * SHA-256 (RFC 7518 §3.4). The raw 64-byte IEEE P1363 signature is
 * base64url-encoded as the third segment.
 *
 * @param payload - The JWT claims to include in the token.
 * @param privateKey - An ECDSA P-256 `CryptoKey` with `sign` usage, e.g. from
 *   {@link generateKeyPair}.
 * @returns A compact JWT string `header.payload.signature`.
 *
 * @example
 * ```ts
 * const { publicKey, privateKey } = await generateKeyPair();
 * const token = await sign({ sub: 'agent-1', aud: 'my-service' }, privateKey);
 * ```
 */
export async function sign(payload: JWTPayload, privateKey: CryptoKey): Promise<string> {
  // Build the header
  const header: JWTHeader = { alg: 'ES256', typ: 'JWT' };

  // Auto-inject iat if not already present
  const finalPayload: JWTPayload = payload.iat !== undefined
    ? { ...payload }
    : { ...payload, iat: Math.floor(Date.now() / 1000) };

  // Encode header and payload as base64url JSON
  const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(finalPayload)));

  // The signing input is the ASCII string "encodedHeader.encodedPayload"
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signingBytes = encoder.encode(signingInput);

  // Sign using Web Crypto — returns raw IEEE P1363 (r || s) format, 64 bytes for P-256
  const signatureBuffer = await crypto.subtle.sign(
    SIGN_ALGORITHM,
    privateKey,
    signingBytes,
  );

  const encodedSignature = base64UrlEncode(new Uint8Array(signatureBuffer));

  return `${signingInput}.${encodedSignature}`;
}
