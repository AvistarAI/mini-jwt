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
export function base64UrlEncode(data: Uint8Array): string {
  // Build a binary string from the byte array
  let binaryString = '';
  for (let i = 0; i < data.length; i++) {
    binaryString += String.fromCharCode(data[i] as number);
  }

  // Encode to standard base64, then transform to base64url
  return btoa(binaryString)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

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
export function base64UrlDecode(str: string): Uint8Array<ArrayBuffer> {
  // Restore standard base64 characters
  const base64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  // Re-add padding
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);

  // Decode
  const binaryString = atob(padded);
  const buffer = new ArrayBuffer(binaryString.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}
