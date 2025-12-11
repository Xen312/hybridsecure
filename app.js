/* app.js — Complete working static frontend for E2E chat
   - Expects API_BASE and GOOGLE_CLIENT_ID to be defined in index.html BEFORE this script runs.
   - Loads libsodium via window.sodium (sodium.js must be loaded before this file).
   - Uses IndexedDB to store encrypted private key (or raw if user skips passphrase).
   - Uses X25519 (libsodium) -> HKDF(SHA-256) -> AES-GCM for encryption.
   - Polls API for new messages every 3 seconds.
*/

(async function () {
  'use strict';

  // ---- Config ----
  const POLL_INTERVAL_MS = 3000;

  // ---- DOM refs ----
  const gsiButtonDiv = document.getElementById('gsi-button');
  const signedInDiv = document.getElementById('signed-in');
  const profileName = document.getElementById('profile-name');
  const profileEmail = document.getElementById('profile-email');
  const signOutBtn = document.getElementById('signOutBtn');
  const usersDiv = document.getElementById('users');
  const messagesDiv = document.getElementById('messages');
  const chatHeader = document.getElementById('chat-header');
  const sendBtn = document.getElementById('sendBtn');
  const msgInput = document.getElementById('messageInput');
  const exportKeyBtn = document.getElementById('exportKeyBtn');
  const importKeyBtn = document.getElementById('importKeyBtn');
  const toastEl = document.getElementById('toast');

  // ---- State ----
  let me = null; // { userId, name, email, idToken }
  let myKeyPair = null; // { publicKey: Uint8Array, privateKey: Uint8Array }
  let users = [];
  let selectedUser = null;
  let lastPollISO = new Date(0).toISOString();
  let polling = false;
  let sodiumLib = null;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---- Utility: toast ----
  function showToast(msg, t = 3000) {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.remove('hidden');
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => toastEl.classList.add('hidden'), t);
  }

  // ---- Ensure libsodium loaded and ready ----
  async function ensureSodiumLoaded(timeoutMs = 10000) {
    const start = Date.now();
    while (typeof window.sodium === 'undefined') {
      if (Date.now() - start > timeoutMs) break;
      await new Promise(r => setTimeout(r, 100));
    }
    if (typeof window.sodium === 'undefined') {
      throw new Error('libsodium not loaded (window.sodium missing)');
    }
    await window.sodium.ready;
    return window.sodium;
  }

  try {
    sodiumLib = await ensureSodiumLoaded(10000);
    console.log('libsodium ready');
  } catch (err) {
    console.error('libsodium failed to load', err);
    alert('Crypto library failed to load. Ensure sodium.js is reachable and not blocked by extensions.');
    return; // stop further execution
  }

  // ---- IndexedDB helpers ----
  function openDB() {
    return new Promise((res, rej) => {
      const req = indexedDB.open('chat-app', 1);
      req.onupgradeneeded = ev => {
        const db = ev.target.result;
        if (!db.objectStoreNames.contains('keys')) db.createObjectStore('keys', { keyPath: 'userId' });
      };
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });
  }

  async function saveKeyRecord(userId, record) {
    const db = await openDB();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', 'readwrite');
      const store = tx.objectStore('keys');
      store.put(Object.assign({ userId }, record));
      tx.oncomplete = () => res(true);
      tx.onerror = () => rej(tx.error);
    });
  }

  async function loadKeyRecord(userId) {
    const db = await openDB();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', 'readonly');
      const req = tx.objectStore('keys').get(userId);
      req.onsuccess = () => res(req.result);
      req.onerror = () => rej(req.error);
    });
  }

  async function deleteKeyRecord(userId) {
    const db = await openDB();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', 'readwrite');
      tx.objectStore('keys').delete(userId);
      tx.oncomplete = () => res(true);
      tx.onerror = () => rej(tx.error);
    });
  }

  // ---- Base64 helpers ----
  function arrayBufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let str = '';
    for (let i = 0; i < bytes.byteLength; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str);
  }
  function base64ToUint8Array(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  // ---- WebCrypto PBKDF2 -> AES-GCM for private key encryption ----
  async function deriveKeyFromPassphrase(passphrase, saltUint8, iterations = 150000) {
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({
      name: 'PBKDF2',
      salt: saltUint8,
      iterations,
      hash: 'SHA-256'
    }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return key;
  }

  async function encryptPrivateKeyWithPassphrase(privateKeyU8, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyFromPassphrase(passphrase, salt);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, privateKeyU8);
    return {
      encryptedPrivateKeyBase64: arrayBufferToBase64(ct),
      kdfSaltBase64: arrayBufferToBase64(salt.buffer),
      kdfIterations: 150000,
      ivBase64: arrayBufferToBase64(iv.buffer),
      encryptedWithPassphrase: true
    };
  }

  async function decryptPrivateKeyWithPassphrase(record, passphrase) {
    const salt = base64ToUint8Array(record.kdfSaltBase64);
    const iv = base64ToUint8Array(record.ivBase64);
    const key = await deriveKeyFromPassphrase(passphrase, salt, record.kdfIterations || 150000);
    const ct = base64ToUint8Array(record.encryptedPrivateKeyBase64);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new Uint8Array(plain);
  }

  // ---- Simple UI helpers ----
  function escapeHtml(s) { if (!s) return ''; return s.replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])); }

  // ---- Google Identity Services (GSI) ----
  function initGSI() {
    window.handleCredentialResponse = async (resp) => {
      try {
        const idToken = resp.credential;
        const payload = JSON.parse(atob(idToken.split('.')[1]));
        me = { userId: payload.sub, name: payload.name || payload.email, email: payload.email, idToken };
        profileName.textContent = me.name;
        profileEmail.textContent = me.email;
        gsiButtonDiv.style.display = 'none';
        signedInDiv.classList.remove('hidden');
        await ensureKeypairForMe();
        await registerPublicKey();
        await refreshUsers();
        startPolling();
        showToast('Signed in: ' + (me.name || me.email));
      } catch (e) {
        console.error('GSI handler error', e);
        showToast('Sign-in failed');
      }
    };

    google.accounts.id.initialize({
      client_id: GOOGLE_CLIENT_ID,
      callback: handleCredentialResponse
    });
    google.accounts.id.renderButton(gsiButtonDiv, { theme: 'outline', size: 'large' });
  }

  // ---- Keypair management ----
  async function createNewKeypairFlow() {
    const kp = sodiumLib.crypto_kx_keypair(); // { publicKey, privateKey }
    myKeyPair = { publicKey: kp.publicKey, privateKey: kp.privateKey };
    const wantPass = confirm('Protect private key with a passphrase? Recommended. OK = set passphrase, Cancel = store unencrypted (less secure).');
    if (wantPass) {
      let pass = null;
      while (!pass) {
        pass = prompt('Choose a passphrase to protect your private key. Remember it—we cannot recover it for you.');
        if (!pass) {
          if (!confirm('No passphrase chosen — store unencrypted?')) continue;
          else break;
        }
      }
      if (pass) {
        const rec = await encryptPrivateKeyWithPassphrase(myKeyPair.privateKey, pass);
        rec.publicKeyBase64 = arrayBufferToBase64(myKeyPair.publicKey.buffer);
        await saveKeyRecord(me.userId, rec);
      } else {
        const rec = { rawPrivateKeyBase64: arrayBufferToBase64(myKeyPair.privateKey.buffer), publicKeyBase64: arrayBufferToBase64(myKeyPair.publicKey.buffer), encryptedWithPassphrase: false };
        await saveKeyRecord(me.userId, rec);
      }
    } else {
      const rec = { rawPrivateKeyBase64: arrayBufferToBase64(myKeyPair.privateKey.buffer), publicKeyBase64: arrayBufferToBase64(myKeyPair.publicKey.buffer), encryptedWithPassphrase: false };
      await saveKeyRecord(me.userId, rec);
    }
  }

  async function ensureKeypairForMe() {
    if (!me) throw new Error('Not signed in');
    const rec = await loadKeyRecord(me.userId);
    if (rec) {
      if (rec.encryptedWithPassphrase) {
        let unlocked = false;
        for (let tries = 0; tries < 3 && !unlocked; tries++) {
          const pass = prompt('Enter passphrase to unlock your private key (Cancel to skip):');
          if (!pass) break;
          try {
            const priv = await decryptPrivateKeyWithPassphrase(rec, pass);
            myKeyPair = { privateKey: priv, publicKey: base64ToUint8Array(rec.publicKeyBase64) };
            unlocked = true;
          } catch (e) {
            alert('Incorrect passphrase');
          }
        }
        if (!unlocked && !myKeyPair) {
          if (confirm('Could not unlock key. Create a new keypair? (You will lose ability to decrypt previous messages)')) {
            await createNewKeypairFlow();
          } else {
            throw new Error('Key unlock aborted');
          }
        }
      } else {
        // raw stored
        const priv = base64ToUint8Array(rec.rawPrivateKeyBase64);
        const pub = rec.publicKeyBase64 ? base64ToUint8Array(rec.publicKeyBase64) : sodiumLib.crypto_scalarmult_base(priv);
        myKeyPair = { privateKey: priv, publicKey: pub };
      }
    } else {
      await createNewKeypairFlow();
    }
  }

  async function registerPublicKey() {
    if (!me || !myKeyPair) return;
    const pkB64 = arrayBufferToBase64(myKeyPair.publicKey.buffer);
    try {
      const r = await fetch(API_BASE, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ idToken: me.idToken, publicKeyBase64: pkB64, name: me.name, email: me.email }) });
      const j = await r.json();
      if (!j.ok) console.warn('registerPublicKey response', j);
    } catch (e) {
      console.warn('registerPublicKey error', e);
    }
  }

  // ---- Users list ----
  async function refreshUsers() {
    usersDiv.textContent = 'Loading...';
    try {
      const r = await fetch(API_BASE + '?action=getUsers');
      const j = await r.json();
      users = (j.users || []).filter(u => !me || u.userId !== me.userId);
      renderUsers();
    } catch (e) {
      usersDiv.textContent = 'Failed to load users';
      console.error(e);
    }
  }

  function renderUsers() {
    usersDiv.innerHTML = '';
    if (!users.length) { usersDiv.textContent = 'No users yet'; return; }
    users.forEach(u => {
      const el = document.createElement('div');
      el.className = 'user-item' + (selectedUser && selectedUser.userId === u.userId ? ' active' : '');
      el.innerHTML = `<div style="flex:1"><div class="name">${escapeHtml(u.name || u.email || u.userId)}</div><div class="email">${escapeHtml(u.email || '')}</div></div>`;
      el.onclick = () => { selectedUser = u; chatHeader.textContent = 'Chat with: ' + (u.name || u.email); messagesDiv.innerHTML = ''; lastPollISO = new Date(0).toISOString(); };
      usersDiv.appendChild(el);
    });
  }

  // ---- Send message ----
  sendBtn.onclick = sendMessage;
  msgInput.onkeydown = (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) sendMessage(); };

  async function sendMessage() {
    const text = msgInput.value.trim();
    if (!text) return;
    if (!me || !myKeyPair || !selectedUser) { showToast('Sign in and select a user'); return; }
    try {
      const recipientPub = base64ToUint8Array(selectedUser.publicKeyBase64);
      const shared = sodiumLib.crypto_scalarmult(myKeyPair.privateKey, recipientPub); // Uint8Array
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const saltB64 = arrayBufferToBase64(salt.buffer);
      const msgId = 'm_' + Date.now() + '_' + Math.floor(Math.random() * 100000);
      const infoStr = `${me.userId}|${selectedUser.userId}|${msgId}`;
      const aesKey = await hkdfImport(shared, salt, infoStr);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const aadStr = `${me.userId}|${selectedUser.userId}|${msgId}`;
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aadStr) }, aesKey, enc.encode(text));
      const payload = {
        idToken: me.idToken,
        action: 'postMessage',
        toUserId: selectedUser.userId,
        ciphertextBase64: arrayBufferToBase64(ct),
        ivBase64: arrayBufferToBase64(iv.buffer),
        saltBase64: saltB64,
        aad: aadStr,
        msgId
      };
      appendMessage({ me: true, text, createdAt: new Date().toISOString() }); // optimistic
      msgInput.value = '';
      const r = await fetch(API_BASE, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const j = await r.json();
      if (!j.ok) showToast('Send failed');
    } catch (e) {
      console.error('sendMessage error', e);
      showToast('Send failed');
    }
  }

  function appendMessage({ me: isMe, text, createdAt }) {
    const div = document.createElement('div');
    div.className = 'msg' + (isMe ? ' me' : '');
    const meta = document.createElement('div'); meta.className = 'meta'; meta.textContent = (isMe ? 'Me' : (selectedUser ? selectedUser.name : 'Other')) + ' • ' + (new Date(createdAt)).toLocaleString();
    const body = document.createElement('div'); body.textContent = text;
    div.appendChild(meta); div.appendChild(body);
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }

  // ---- Polling ----
  async function pollOnce() {
    if (!me) return;
    try {
      const url = `${API_BASE}?action=getMessages&toUserId=${encodeURIComponent(me.userId)}&since=${encodeURIComponent(lastPollISO)}&idToken=${encodeURIComponent(me.idToken)}`;
      const r = await fetch(url);
      const j = await r.json();
      if (j.messages && j.messages.length) {
        lastPollISO = new Date().toISOString();
        for (const m of j.messages) {
          let sender = users.find(u => u.userId === m.fromUserId);
          if (!sender) {
            await refreshUsers();
            sender = users.find(u => u.userId === m.fromUserId) || { userId: m.fromUserId, name: m.fromUserId, publicKeyBase64: null };
          }
          if (!sender.publicKeyBase64) { console.warn('Missing sender public key', m.fromUserId); continue; }
          try {
            const senderPub = base64ToUint8Array(sender.publicKeyBase64);
            const shared = sodiumLib.crypto_scalarmult(myKeyPair.privateKey, senderPub);
            const salt = base64ToUint8Array(m.saltBase64);
            const aesKey = await hkdfImport(shared, salt, `${m.fromUserId}|${m.toUserId}|${m.msgId}`);
            const iv = base64ToUint8Array(m.ivBase64);
            const ct = base64ToUint8Array(m.ciphertextBase64);
            const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(m.aad) }, aesKey, ct);
            const text = dec.decode(plainBuf);
            if (selectedUser && selectedUser.userId === m.fromUserId) {
              appendMessage({ me: false, text, createdAt: m.createdAt });
            } else {
              showToast(`New message from ${sender.name || sender.userId}`);
            }
          } catch (e) {
            console.warn('Decrypt failed for message', m.msgId, e);
          }
        }
      }
    } catch (e) {
      console.warn('pollOnce error', e);
    }
  }

  function startPolling() {
    if (polling) return;
    polling = true;
    (async function loop() {
      while (polling) {
        try { await pollOnce(); } catch (e) { console.warn(e); }
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
      }
    })();
  }

  function stopPolling() { polling = false; }

  // ---- HKDF import (derive AES-GCM 256 key) ----
  async function hkdfImport(sharedUint8, saltUint8, infoStr) {
    const ikm = sharedUint8.buffer ? sharedUint8.buffer : sharedUint8;
    const salt = saltUint8.buffer ? saltUint8.buffer : saltUint8;
    const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: enc.encode(infoStr || '')
    }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    return derivedKey;
  }

  // ---- Export / Import key ----
  exportKeyBtn.onclick = async () => {
    if (!me) return showToast('Sign in first');
    const rec = await loadKeyRecord(me.userId);
    if (!rec) return showToast('No key to export');
    const blob = new Blob([JSON.stringify(rec)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `chat-key-${me.userId}.json`; document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    showToast('Key exported');
  };

  importKeyBtn.onclick = async () => {
    const input = document.createElement('input'); input.type = 'file'; input.accept = 'application/json';
    input.onchange = async (e) => {
      const f = e.target.files[0];
      if (!f) return;
      const text = await f.text();
      let rec;
      try { rec = JSON.parse(text); } catch (err) { return showToast('Invalid key file'); }
      if (!me) return showToast('Sign in first to import key');
      await saveKeyRecord(me.userId, rec);
      showToast('Key imported');
      await ensureKeypairForMe();
    };
    input.click();
  };

  // ---- Sign out ----
  signOutBtn.onclick = () => {
    me = null; myKeyPair = null; selectedUser = null;
    signedInDiv.classList.add('hidden');
    gsiButtonDiv.style.display = 'block';
    messagesDiv.innerHTML = ''; usersDiv.innerHTML = '';
    stopPolling();
    try { google.accounts.id.disableAutoSelect(); } catch (e) { /* ignore */ }
    showToast('Signed out');
  };

  // ---- Init UI and start ----
  try {
    initGSI();
    refreshUsers();
  } catch (e) {
    console.error('Initialization error', e);
  }

})();
