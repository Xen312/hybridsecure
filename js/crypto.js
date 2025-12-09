// crypto.js
import { base64UrlToU8, u8ToBase64Url } from './utils.js';

// crypto.js — libsodium loader (updated)
export async function initSodium() {
  // libsodium may be available as window.libsodium or window.sodium depending on build
  const lib = (window.libsodium || window.sodium || window.libsodium_wrappers);
  if (!lib) {
    throw new Error("libsodium not found on window. Ensure you loaded the browser UMD build before your app. Use: https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.9/dist/browsers/sodium.js");
  }
  // `ready` is a Promise on the libsodium object
  await lib.ready;
  return lib;
}


export function computeShared(sodium, mySkU8, theirPkU8) {
  return sodium.crypto_scalarmult(mySkU8, theirPkU8);
}

export async function deriveAesKey(sharedU8, saltU8, infoStr) {
  const info = new TextEncoder().encode(infoStr);
  const hkdfKey = await crypto.subtle.importKey("raw", sharedU8, { name: "HKDF" }, false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: saltU8, info },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt","decrypt"]
  );
  return aesKey;
}

export async function aesEncrypt(aesKey, ivU8, adU8, plaintextStr) {
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv: ivU8, additionalData: adU8, tagLength:128 }, aesKey, new TextEncoder().encode(plaintextStr));
  return new Uint8Array(ct);
}

export async function aesDecrypt(aesKey, ivU8, adU8, ctU8) {
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv: ivU8, additionalData: adU8, tagLength:128 }, aesKey, ctU8);
  return new TextDecoder().decode(pt);
}

export { base64UrlToU8, u8ToBase64Url };
