/**
 * Agent Identity Token (AIT) SDK
 * A minimal JWT-like identity token system for AI agents using Web Crypto API.
 */

export const VERSION = '0.1.0';

export { generateKeyPair } from './keys.js';
export { sign } from './sign.js';
export { verify } from './verify.js';
export { decode } from './decode.js';
export { base64UrlEncode, base64UrlDecode } from './base64url.js';
export type { JWTHeader, JWTPayload, VerifyResult, KeyPair } from './types.js';
