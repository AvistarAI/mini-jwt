/**
 * Core TypeScript interfaces for the Agent Identity Token (AIT) standard.
 * @module types
 */

/**
 * JWT header as defined by the AIT standard.
 * Fixed to ES256 algorithm and JWT type.
 */
export interface JWTHeader {
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
export interface JWTPayload {
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
export interface VerifyResult {
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
export interface KeyPair {
  /** Public key used for token verification. */
  publicKey: CryptoKey;
  /** Private key used for token signing. */
  privateKey: CryptoKey;
}
