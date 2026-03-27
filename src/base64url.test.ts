import { describe, it, expect } from 'vitest';
import { base64UrlEncode, base64UrlDecode } from './base64url.js';

describe('base64UrlEncode()', () => {
  it('encodes "hello" to "aGVsbG8"', () => {
    const bytes = new TextEncoder().encode('hello');
    expect(base64UrlEncode(bytes)).toBe('aGVsbG8');
  });

  it('produces no padding characters', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const result = base64UrlEncode(bytes);
    expect(result).not.toContain('=');
  });

  it('uses - instead of +', () => {
    // Find a byte sequence that would produce + in standard base64
    // 0xFB = 11111011 -> together with neighbors would produce '+'
    const bytes = new Uint8Array([0xfb, 0xff]);
    const result = base64UrlEncode(bytes);
    expect(result).not.toContain('+');
  });

  it('uses _ instead of /', () => {
    const bytes = new Uint8Array([0xff, 0xff]);
    const result = base64UrlEncode(bytes);
    expect(result).not.toContain('/');
  });

  it('handles an empty Uint8Array', () => {
    expect(base64UrlEncode(new Uint8Array(0))).toBe('');
  });
});

describe('base64UrlDecode()', () => {
  it('decodes "aGVsbG8" back to the bytes for "hello"', () => {
    const bytes = base64UrlDecode('aGVsbG8');
    expect(new TextDecoder().decode(bytes)).toBe('hello');
  });

  it('round-trips arbitrary binary data', () => {
    const original = new Uint8Array([0, 1, 127, 128, 255]);
    const encoded = base64UrlEncode(original);
    const decoded = base64UrlDecode(encoded);
    expect(decoded).toEqual(original);
  });

  it('handles an empty string', () => {
    expect(base64UrlDecode('')).toEqual(new Uint8Array(0));
  });
});
