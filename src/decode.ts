/**
 * JWT decode utility — extracts the payload without verifying the signature.
 * @module decode
 */

import { base64UrlDecode } from './base64url.js';
import type { JWTPayload } from './types.js';

/**
 * Decodes the payload of a JWT token **without** verifying its signature.
 *
 * Use this function when you only need to read claims and have already
 * verified the token through another means, or when building debugging
 * tooling. For secure, production use always call `verify()` instead.
 *
 * @param token - A compact JWT string in the format `header.payload.signature`.
 * @returns The decoded {@link JWTPayload} object.
 * @throws {Error} If the token does not have exactly three dot-separated segments.
 * @throws {Error} If the payload segment is not valid base64url.
 * @throws {Error} If the decoded payload bytes are not valid JSON.
 *
 * @example
 * const payload = decode(token);
 * console.log(payload.sub); // "agent-123"
 */
export function decode(token: string): JWTPayload {
  const parts = token.split('.');

  if (parts.length !== 3) {
    throw new Error(
      `Malformed JWT: expected 3 dot-separated segments, got ${parts.length}.`,
    );
  }

  const payloadSegment = parts[1] as string;

  let payloadBytes: Uint8Array;
  try {
    payloadBytes = base64UrlDecode(payloadSegment);
  } catch {
    throw new Error('Malformed JWT: payload segment is not valid base64url.');
  }

  const payloadJson = new TextDecoder().decode(payloadBytes);

  let payload: unknown;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    throw new Error('Malformed JWT: payload segment is not valid JSON.');
  }

  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('Malformed JWT: payload must be a JSON object.');
  }

  return payload as JWTPayload;
}
