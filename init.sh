#!/usr/bin/env bash
set -euo pipefail

# Mini JWT Library — Project Initializer
# Creates the full project scaffold under output/

echo "🔧 Initializing mini-jwt project..."

# ── Directories ──────────────────────────────────────────────────────────────
mkdir -p src tests

# ── package.json ─────────────────────────────────────────────────────────────
cat > package.json <<'EOF'
{
  "name": "mini-jwt",
  "version": "0.1.0",
  "description": "Minimal JWT library using Web Crypto API (ES256 only)",
  "type": "module",
  "main": "./dist/index.js",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsup",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit"
  },
  "devDependencies": {
    "tsup": "^8.0.0",
    "typescript": "^5.4.0",
    "vitest": "^1.4.0"
  }
}
EOF

# ── tsconfig.json ─────────────────────────────────────────────────────────────
cat > tsconfig.json <<'EOF'
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "lib": ["ES2022", "DOM"],
    "outDir": "./dist",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
EOF

# ── vitest.config.ts ──────────────────────────────────────────────────────────
cat > vitest.config.ts <<'EOF'
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: false,
  },
});
EOF

# ── tsup.config.ts ────────────────────────────────────────────────────────────
cat > tsup.config.ts <<'EOF'
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
});
EOF

# ── src/ stubs ────────────────────────────────────────────────────────────────
cat > src/types.ts <<'EOF'
// Core types — to be implemented in F002
export interface JWTHeader {
  alg: "ES256";
  typ: "JWT";
  kid?: string;
}

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nbf?: number;
  jti?: string;
  [key: string]: unknown;
}

export interface VerifyResult {
  valid: boolean;
  payload: JWTPayload;
  errors: string[];
}

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}
EOF

touch src/base64url.ts
touch src/keys.ts
touch src/sign.ts
touch src/verify.ts
touch src/decode.ts

cat > src/index.ts <<'EOF'
// Public API — re-exports to be filled in as features are implemented
export type { JWTHeader, JWTPayload, VerifyResult, KeyPair } from "./types.js";
EOF

# ── test stubs ────────────────────────────────────────────────────────────────
cat > tests/sign.test.ts <<'EOF'
import { describe, it } from "vitest";

describe("sign", () => {
  it.todo("produces a three-segment compact JWS");
});
EOF

cat > tests/verify.test.ts <<'EOF'
import { describe, it } from "vitest";

describe("verify", () => {
  it.todo("returns valid=true for a well-formed token");
});
EOF

cat > tests/decode.test.ts <<'EOF'
import { describe, it } from "vitest";

describe("decode", () => {
  it.todo("decodes payload without verifying signature");
});
EOF

cat > tests/edge-cases.test.ts <<'EOF'
import { describe, it } from "vitest";

describe("edge cases", () => {
  it.todo("rejects tokens signed with a different key");
});
EOF

# ── Install dependencies ──────────────────────────────────────────────────────
echo "📦 Installing dependencies..."
npm install

echo ""
echo "✅ mini-jwt project initialized successfully!"
echo ""
echo "Next steps:"
echo "  npm test        — run test suite"
echo "  npm run build   — bundle with tsup"
echo "  npm run typecheck — type-check without emitting"
