// crypto.js
import crypto from "crypto";

export function generateX25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");

  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64")
  };
}

export function computeSharedSecret(privateKeyB64, publicKeyB64) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8"
  });

  const publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKeyB64, "base64"),
    format: "der",
    type: "spki"
  });

  return crypto.diffieHellman({ privateKey, publicKey });
}

export function deriveAESKey(sharedSecret, chatId) {
  return crypto.hkdfSync(
    "sha256",
    sharedSecret,
    Buffer.from(chatId),
    Buffer.from("HybridSecure AES-GCM Key"),
    32
  );
}

export function encryptAESGCM(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final()
  ]);

  return {
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64")
  };
}

export function decryptAESGCM(key, ivB64, ciphertextB64, authTagB64) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivB64, "base64")
  );

  decipher.setAuthTag(Buffer.from(authTagB64, "base64"));

  return decipher.update(ciphertextB64, "base64", "utf8") +
         decipher.final("utf8");
}

// crypto.js
import crypto from "crypto";

export function generateX25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");

  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64")
  };
}

export function computeSharedSecret(privateKeyB64, publicKeyB64) {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8"
  });

  const publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKeyB64, "base64"),
    format: "der",
    type: "spki"
  });

  return crypto.diffieHellman({ privateKey, publicKey });
}

export function deriveAESKey(sharedSecret, chatId) {
  return crypto.hkdfSync(
    "sha256",
    sharedSecret,
    Buffer.from(chatId),
    Buffer.from("HybridSecure AES-GCM Key"),
    32
  );
}

export function encryptAESGCM(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final()
  ]);

  return {
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64")
  };
}

export function decryptAESGCM(key, ivB64, ciphertextB64, authTagB64) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivB64, "base64")
  );

  decipher.setAuthTag(Buffer.from(authTagB64, "base64"));

  return decipher.update(ciphertextB64, "base64", "utf8") +
         decipher.final("utf8");
}