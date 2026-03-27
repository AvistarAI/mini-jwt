/**
 * JWT verification utilities for the Agent Identity Token (AIT) standard.
 * Uses the Web Crypto API to validate the ECDSA P-256 signature on a JWT token.
 * @module verify
 */

import { base64UrlDecode } from './base64url.js';
import type { JWTPayload, VerifyResult } from './types.js';

/** Text encoder singleton — reused to avoid repeated allocations. */
const encoder = new TextEncoder();

/** ECDSA verification algorithm parameters (P-256 with SHA-256). */
const VERIFY_ALGORITHM: EcdsaParams = {
  name: 'ECDSA',
  hash: { name: 'SHA-256' },
};

/**
 * Verifies the ECDSA P-256 signature of a compact JWT string.
 *
 * The function splits the token into its three dot-separated segments, re-encodes
 * the signing input (`header.payload`) as UTF-8 bytes, decodes the signature
 * from base64url, and calls `crypto.subtle.verify` with the supplied public key.
 *
 * If the signature is valid the decoded payload is returned in `VerifyResult.payload`.
 * If the token is malformed (wrong segment count, invalid base64url, invalid JSON) or
 * the signature does not match, `VerifyResult.valid` is `false` and `VerifyResult.errors`
 * contains at least one human-readable message describing the problem.
 *
 * @param token     - A compact JWT string in the format `header.payload.signature`.
 * @param publicKey - An ECDSA P-256 `CryptoKey` with `verify` usage, e.g. from
 *   {@link generateKeyPair}.
 * @returns A {@link VerifyResult} indicating whether the token is valid.
 *
 * @example
 * ```ts
 * const { publicKey, privateKey } = await generateKeyPair();
 * const token = await sign({ sub: 'agent-1' }, privateKey);
 * const result = await verify(token, publicKey);
 * // result.valid === true
 * // result.payload?.sub === 'agent-1'
 * ```
 */
export async function verify(token: string, publicKey: CryptoKey): Promise<VerifyResult> {
  const errors: string[] = [];

  // ── 1. Structural validation ──────────────────────────────────────────────
  const parts = token.split('.');
  if (parts.length !== 3) {
    errors.push(
      `Malformed JWT: expected 3 dot-separated segments, got ${parts.length}.`,
    );
    return { valid: false, errors };
  }

  const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

  // ── 2. Decode the signature segment ──────────────────────────────────────
  let signatureBuffer: ArrayBuffer;
  try {
    signatureBuffer = base64UrlDecode(signatureSegment).buffer;
  } catch {
    errors.push('Malformed JWT: signature segment is not valid base64url.');
    return { valid: false, errors };
  }

  // ── 3. Decode the payload segment ────────────────────────────────────────
  let payloadBytes: Uint8Array<ArrayBuffer>;
  try {
    payloadBytes = base64UrlDecode(payloadSegment);
  } catch {
    errors.push('Malformed JWT: payload segment is not valid base64url.');
    return { valid: false, errors };
  }

  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    errors.push('Malformed JWT: payload segment is not valid JSON.');
    return { valid: false, errors };
  }

  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    errors.push('Malformed JWT: payload must be a JSON object.');
    return { valid: false, errors };
  }

  // ── 4. Cryptographic signature verification ───────────────────────────────
  // The signing input is exactly the ASCII bytes of "encodedHeader.encodedPayload"
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const signingInputBuffer: ArrayBuffer = encoder.encode(signingInput).buffer as ArrayBuffer;

  let signatureValid: boolean;
  try {
    signatureValid = await crypto.subtle.verify(
      VERIFY_ALGORITHM,
      publicKey,
      signatureBuffer,
      signingInputBuffer,
    );
  } catch (err) {
    // crypto.subtle.verify can throw if the key is wrong type / algorithm mismatch
    const message = err instanceof Error ? err.message : String(err);
    errors.push(`Signature verification error: ${message}`);
    return { valid: false, errors };
  }

  if (!signatureValid) {
    errors.push('Invalid signature: the token signature does not match the public key.');
    return { valid: false, errors };
  }

  // ── 5. Claims validation ───────────────────────────────────────────────────
  const claims = payload as JWTPayload;
  const nowSeconds = Math.floor(Date.now() / 1000);

  // exp — expiration time
  if (typeof claims.exp === 'number' && nowSeconds >= claims.exp) {
    errors.push(`Token is expired: exp (${claims.exp}) is in the past (current time: ${nowSeconds}).`);
  }

  // nbf — not before time
  if (typeof claims.nbf === 'number' && nowSeconds < claims.nbf) {
    errors.push(`Token is not yet valid: nbf (${claims.nbf}) is in the future (current time: ${nowSeconds}).`);
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  // ── 6. All checks passed ──────────────────────────────────────────────────
  return {
    valid: true,
    payload: claims,
    errors: [],
  };
}
