// crypto.js — libsodium + WebCrypto helpers
import { base64UrlToU8, u8ToBase64Url } from './utils.js';

export async function initSodium() {
  await libsodium.ready;
  return libsodium;
}

export function computeShared(sodium, mySkU8, theirPkU8) {
  return sodium.crypto_scalarmult(mySkU8, theirPkU8);
}

export async function deriveAesKey(sharedU8, saltU8, infoStr) {
  const info = new TextEncoder().encode(infoStr);
  const hkdfKey = await crypto.subtle.importKey("raw", sharedU8, "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name:"HKDF", hash:"SHA-256", salt: saltU8, info },
    hkdfKey,
    { name:"AES-GCM", length:256 },
    false,
    ["encrypt","decrypt"]
  );
  return aesKey;
}

export async function aesEncrypt(aesKey, ivU8, adU8, plaintext) {
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv: ivU8, additionalData: adU8, tagLength:128 }, aesKey, new TextEncoder().encode(plaintext));
  return new Uint8Array(ct);
}

export async function aesDecrypt(aesKey, ivU8, adU8, ctU8) {
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv: ivU8, additionalData: adU8, tagLength:128 }, aesKey, ctU8);
  return new TextDecoder().decode(pt);
}

export { base64UrlToU8, u8ToBase64Url };
