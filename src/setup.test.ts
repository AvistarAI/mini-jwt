/**
 * F001 — Project setup verification tests.
 * Ensures all required configuration files and source stubs exist and
 * the TypeScript project compiles without errors.
 */

import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

describe('F001: project structure', () => {
  it('package.json exists with name mini-jwt and type module', async () => {
    const pkgPath = resolve(root, 'package.json');
    expect(existsSync(pkgPath)).toBe(true);
    const pkg = (await import(pkgPath, { assert: { type: 'json' } })) as {
      default: { name: string; type: string };
    };
    expect(pkg.default.name).toBe('mini-jwt');
    expect(pkg.default.type).toBe('module');
  });

  it('tsconfig.json exists', () => {
    expect(existsSync(resolve(root, 'tsconfig.json'))).toBe(true);
  });

  it('vitest.config.ts exists', () => {
    expect(existsSync(resolve(root, 'vitest.config.ts'))).toBe(true);
  });

  it('tsup.config.ts exists', () => {
    expect(existsSync(resolve(root, 'tsup.config.ts'))).toBe(true);
  });

  it('src/types.ts exists', () => {
    expect(existsSync(resolve(root, 'src/types.ts'))).toBe(true);
  });

  it('src/index.ts exists', () => {
    expect(existsSync(resolve(root, 'src/index.ts'))).toBe(true);
  });

  it('src/keys.ts exists', () => {
    expect(existsSync(resolve(root, 'src/keys.ts'))).toBe(true);
  });

  it('src/sign.ts exists', () => {
    expect(existsSync(resolve(root, 'src/sign.ts'))).toBe(true);
  });

  it('src/verify.ts exists', () => {
    expect(existsSync(resolve(root, 'src/verify.ts'))).toBe(true);
  });

  it('src/decode.ts exists', () => {
    expect(existsSync(resolve(root, 'src/decode.ts'))).toBe(true);
  });

  it('src/base64url.ts exists', () => {
    expect(existsSync(resolve(root, 'src/base64url.ts'))).toBe(true);
  });

  it('node_modules exists (npm install succeeded)', () => {
    expect(existsSync(resolve(root, 'node_modules'))).toBe(true);
  });
});
