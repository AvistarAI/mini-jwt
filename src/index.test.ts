import { describe, it, expect } from 'vitest';
import { VERSION } from './index.js';

describe('index', () => {
  it('exports a VERSION string', () => {
    expect(typeof VERSION).toBe('string');
    expect(VERSION).toBe('0.1.0');
  });
});
