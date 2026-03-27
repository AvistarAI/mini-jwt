/**
 * Core TypeScript interfaces for the Agent Identity Token (AIT) standard.
 * @module types
 */
/**
 * JWT header as defined by the AIT standard.
 * Fixed to ES256 algorithm and JWT type.
 */
interface JWTHeader {
    /** Algorithm — always 'ES256' for AIT tokens. */
    alg: 'ES256';
    /** Token type — always 'JWT'. */
    typ: 'JWT';
    /** Optional key ID hint for key rotation/selection. */
    kid?: string;
}
/**
 * JWT payload containing optional standard registered claims
 * plus any additional application-defined claims.
 */
interface JWTPayload {
    /** Issuer — identifies the principal that issued the JWT. */
    iss?: string;
    /** Subject — identifies the principal that is the subject of the JWT. */
    sub?: string;
    /** Audience — identifies the recipient(s) the JWT is intended for. */
    aud?: string | string[];
    /** Expiration time — Unix timestamp after which the JWT must not be accepted. */
    exp?: number;
    /** Not before — Unix timestamp before which the JWT must not be accepted. */
    nbf?: number;
    /** Issued at — Unix timestamp when the JWT was issued. */
    iat?: number;
    /** JWT ID — unique identifier for the JWT. */
    jti?: string;
    /** Additional application-defined claims. */
    [key: string]: unknown;
}
/**
 * Result returned by the `verify()` function.
 */
interface VerifyResult {
    /** Whether the token passed all validation checks. */
    valid: boolean;
    /**
     * The decoded payload, present only when the token is valid.
     * Undefined when `valid` is false.
     */
    payload?: JWTPayload;
    /** Validation error messages collected during verification. Empty when valid. */
    errors: string[];
}
/**
 * An asymmetric key pair for signing and verifying AIT tokens.
 * Both keys are ECDSA P-256 (ES256) CryptoKey objects from the Web Crypto API.
 */
interface KeyPair {
    /** Public key used for token verification. */
    publicKey: CryptoKey;
    /** Private key used for token signing. */
    privateKey: CryptoKey;
}

/**
 * Key generation utilities for the Agent Identity Token (AIT) standard.
 * Uses the Web Crypto API to generate ES256 (ECDSA P-256) key pairs.
 * @module keys
 */

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
declare function generateKeyPair(): Promise<KeyPair>;

/**
 * JWT signing utilities for the Agent Identity Token (AIT) standard.
 * Uses the Web Crypto API to produce compact ES256-signed JWT strings.
 * @module sign
 */

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
declare function sign(payload: JWTPayload, privateKey: CryptoKey): Promise<string>;

/**
 * JWT verification utilities for the Agent Identity Token (AIT) standard.
 * Uses the Web Crypto API to validate the ECDSA P-256 signature on a JWT token.
 * @module verify
 */

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
declare function verify(token: string, publicKey: CryptoKey): Promise<VerifyResult>;

/**
 * JWT decode utility — extracts the payload without verifying the signature.
 * @module decode
 */

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
declare function decode(token: string): JWTPayload;

/**
 * Base64URL encoding and decoding utilities.
 * Uses only standard Web APIs (btoa/atob) — no external dependencies.
 */
/**
 * Encodes a Uint8Array to a base64url string without padding.
 *
 * Base64url encoding differs from standard base64 in three ways:
 * - `+` is replaced with `-`
 * - `/` is replaced with `_`
 * - `=` padding characters are removed
 *
 * @param data - The binary data to encode.
 * @returns A base64url-encoded string with no padding.
 *
 * @example
 * const bytes = new TextEncoder().encode('hello');
 * base64UrlEncode(bytes); // "aGVsbG8"
 */
declare function base64UrlEncode(data: Uint8Array): string;
/**
 * Decodes a base64url string back to a Uint8Array.
 *
 * Reverses the base64url encoding: restores `-` to `+`, `_` to `/`,
 * re-adds `=` padding as needed, then decodes via atob.
 *
 * @param str - A base64url-encoded string (no padding, using `-` and `_`).
 * @returns The decoded binary data as a Uint8Array.
 * @throws {Error} If the input is not valid base64url.
 *
 * @example
 * base64UrlDecode("aGVsbG8"); // Uint8Array for "hello"
 */
declare function base64UrlDecode(str: string): Uint8Array<ArrayBuffer>;

/**
 * Agent Identity Token (AIT) SDK
 * A minimal JWT-like identity token system for AI agents using Web Crypto API.
 */
declare const VERSION = "0.1.0";

export { type JWTHeader, type JWTPayload, type KeyPair, VERSION, type VerifyResult, base64UrlDecode, base64UrlEncode, decode, generateKeyPair, sign, verify };
