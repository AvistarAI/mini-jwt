// src/keys.ts
var ECDSA_PARAMS = {
  name: "ECDSA",
  namedCurve: "P-256"
};
async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    ECDSA_PARAMS,
    /* extractable */
    true,
    /* usages */
    ["sign", "verify"]
  );
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey
  };
}

// src/base64url.ts
function base64UrlEncode(data) {
  let binaryString = "";
  for (let i = 0; i < data.length; i++) {
    binaryString += String.fromCharCode(data[i]);
  }
  return btoa(binaryString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64UrlDecode(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binaryString = atob(padded);
  const buffer = new ArrayBuffer(binaryString.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// src/sign.ts
var encoder = new TextEncoder();
var SIGN_ALGORITHM = {
  name: "ECDSA",
  hash: { name: "SHA-256" }
};
async function sign(payload, privateKey) {
  const header = { alg: "ES256", typ: "JWT" };
  const finalPayload = payload.iat !== void 0 ? { ...payload } : { ...payload, iat: Math.floor(Date.now() / 1e3) };
  const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(finalPayload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signingBytes = encoder.encode(signingInput);
  const signatureBuffer = await crypto.subtle.sign(
    SIGN_ALGORITHM,
    privateKey,
    signingBytes
  );
  const encodedSignature = base64UrlEncode(new Uint8Array(signatureBuffer));
  return `${signingInput}.${encodedSignature}`;
}

// src/verify.ts
var encoder2 = new TextEncoder();
var VERIFY_ALGORITHM = {
  name: "ECDSA",
  hash: { name: "SHA-256" }
};
async function verify(token, publicKey) {
  const errors = [];
  const parts = token.split(".");
  if (parts.length !== 3) {
    errors.push(
      `Malformed JWT: expected 3 dot-separated segments, got ${parts.length}.`
    );
    return { valid: false, errors };
  }
  const [headerSegment, payloadSegment, signatureSegment] = parts;
  let signatureBuffer;
  try {
    signatureBuffer = base64UrlDecode(signatureSegment).buffer;
  } catch {
    errors.push("Malformed JWT: signature segment is not valid base64url.");
    return { valid: false, errors };
  }
  let payloadBytes;
  try {
    payloadBytes = base64UrlDecode(payloadSegment);
  } catch {
    errors.push("Malformed JWT: payload segment is not valid base64url.");
    return { valid: false, errors };
  }
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    errors.push("Malformed JWT: payload segment is not valid JSON.");
    return { valid: false, errors };
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    errors.push("Malformed JWT: payload must be a JSON object.");
    return { valid: false, errors };
  }
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const signingInputBuffer = encoder2.encode(signingInput).buffer;
  let signatureValid;
  try {
    signatureValid = await crypto.subtle.verify(
      VERIFY_ALGORITHM,
      publicKey,
      signatureBuffer,
      signingInputBuffer
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    errors.push(`Signature verification error: ${message}`);
    return { valid: false, errors };
  }
  if (!signatureValid) {
    errors.push("Invalid signature: the token signature does not match the public key.");
    return { valid: false, errors };
  }
  return {
    valid: true,
    payload,
    errors: []
  };
}

// src/decode.ts
function decode(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error(
      `Malformed JWT: expected 3 dot-separated segments, got ${parts.length}.`
    );
  }
  const payloadSegment = parts[1];
  let payloadBytes;
  try {
    payloadBytes = base64UrlDecode(payloadSegment);
  } catch {
    throw new Error("Malformed JWT: payload segment is not valid base64url.");
  }
  const payloadJson = new TextDecoder().decode(payloadBytes);
  let payload;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    throw new Error("Malformed JWT: payload segment is not valid JSON.");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new Error("Malformed JWT: payload must be a JSON object.");
  }
  return payload;
}

// src/index.ts
var VERSION = "0.1.0";
export {
  VERSION,
  base64UrlDecode,
  base64UrlEncode,
  decode,
  generateKeyPair,
  sign,
  verify
};
//# sourceMappingURL=index.js.map