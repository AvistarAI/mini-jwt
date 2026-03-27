import { describe, it, expect } from 'vitest';
import { VERSION } from './index.js';
import {
  generateKeyPair,
  sign,
  verify,
  decode,
  base64UrlEncode,
  base64UrlDecode,
} from './index.js';

describe('index', () => {
  it('exports a VERSION string', () => {
    expect(typeof VERSION).toBe('string');
    expect(VERSION).toBe('0.1.0');
  });
});

describe('F033: public API exports from index', () => {
  it('exports generateKeyPair as a function', () => {
    expect(typeof generateKeyPair).toBe('function');
  });

  it('exports sign as a function', () => {
    expect(typeof sign).toBe('function');
  });

  it('exports verify as a function', () => {
    expect(typeof verify).toBe('function');
  });

  it('exports decode as a function', () => {
    expect(typeof decode).toBe('function');
  });

  it('exports base64UrlEncode as a function', () => {
    expect(typeof base64UrlEncode).toBe('function');
  });

  it('exports base64UrlDecode as a function', () => {
    expect(typeof base64UrlDecode).toBe('function');
  });
});
