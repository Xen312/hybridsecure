/* app.js
   - Uses libsodium for X25519
   - Stores private key in IndexedDB (encrypted via passphrase if chosen)
   - Uses Web Crypto HKDF + AES-GCM for message encryption/decryption
   - Polls API_BASE for messages to current user (every 3s)
*/

(async function(){
  // ---- Configurable values ----
  const POLL_INTERVAL_MS = 3000; // recommended 3s for prototype
  const RETENTION_DAYS = 30; // informational only (backend enforces)
  // API_BASE and GOOGLE_CLIENT_ID are declared in index.html

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
  document.getElementById('pollIntervalDisplay').textContent = (POLL_INTERVAL_MS/1000) + 's';

  // ---- State ----
  let me = null; // { userId, name, email, idToken }
  let myKeyPair = null; // { publicKey Uint8Array, privateKey Uint8Array }
  let users = []; // other users list
  let selectedUser = null;
  let lastPollISO = new Date(0).toISOString();
  let polling = false;
  let sodiumLib = null;

  // ---- Initialize libsodium (safe) ----
  if (typeof sodium === 'undefined') {
    // Helpful error if the lib didn't load (e.g., blocked or wrong script)
    console.error('libsodium not found. Make sure you included the UMD/browser build: https://cdn.jsdelivr.net/npm/libsodium-wrappers@0.7.9/dist/browsers/sodium.js');
    showToast('Crypto library failed to load. Disable extensions that block third-party scripts or fix index.html script tag.');
    throw new Error('libsodium not loaded');
  }
  await sodium.ready; // wait for libsodium initialization
  sodiumLib = sodium;


  // ---- IndexedDB utilities (simple) ----
  function openDB(){
    return new Promise((res, rej) => {
      const req = indexedDB.open('chat-app', 1);
      req.onupgradeneeded = ev => {
        const db = ev.target.result;
        if (!db.objectStoreNames.contains('keys')) db.createObjectStore('keys', { keyPath: 'userId' });
      };
      req.onsuccess = () => res(req.result);
      req.onerror = (e) => rej(e);
    });
  }

  async function saveKeyEncrypted(userId, encryptedObj){
    const db = await openDB();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys','readwrite');
      tx.objectStore('keys').put(Object.assign({ userId }, encryptedObj));
      tx.oncomplete = () => res(true);
      tx.onerror = e => rej(e);
    });
  }
  async function loadKeyRecord(userId){
    const db = await openDB();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys','readonly');
      const req = tx.objectStore('keys').get(userId);
      req.onsuccess = () => res(req.result);
      req.onerror = e => rej(e);
    });
  }
  async function deleteKeyRecord(userId){
    const db = await openDB();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys','readwrite');
      const req = tx.objectStore('keys').delete(userId);
      req.onsuccess = () => res(true);
      req.onerror = e => rej(e);
    });
  }

  // ---- Web Crypto helpers ----
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  async function deriveKeyFromPassphrase(passphrase, saltBase64, iterations = 150000){
    const salt = base64ToUint8Array(saltBase64);
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256'
    }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
    return key;
  }

  async function encryptPrivateKeyWithPassphrase(privateKeyU8, passphrase){
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const saltB64 = arrayBufferToBase64(salt.buffer);
    const ivB64 = arrayBufferToBase64(iv.buffer);
    const key = await deriveKeyFromPassphrase(passphrase, saltB64);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, privateKeyU8);
    return {
      encryptedPrivateKeyBase64: arrayBufferToBase64(ct),
      kdfSaltBase64: saltB64,
      kdfIterations: 150000,
      ivBase64: ivB64,
      encryptedWithPassphrase: true
    };
  }

  async function decryptPrivateKeyWithPassphrase(record, passphrase){
    const key = await deriveKeyFromPassphrase(passphrase, record.kdfSaltBase64, record.kdfIterations);
    const iv = base64ToUint8Array(record.ivBase64);
    const ct = base64ToUint8Array(record.encryptedPrivateKeyBase64);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new Uint8Array(plain);
  }

  // fallback: store raw private key (not recommended)
  function recordFromRawPrivateKey(rawPrivU8){
    return { rawPrivateKeyBase64: arrayBufferToBase64(rawPrivU8.buffer), encryptedWithPassphrase: false };
  }
  function rawPrivateKeyFromRecord(rec){
    return base64ToUint8Array(rec.rawPrivateKeyBase64);
  }

  // ---- Base64 helpers ----
  function arrayBufferToBase64(buf){
    const bytes = new Uint8Array(buf);
    let str = '';
    for (let i=0;i<bytes.length;i++) str += String.fromCharCode(bytes[i]);
    return btoa(str);
  }
  function base64ToUint8Array(b64){
    const bin = atob(b64);
    const len = bin.length;
    const arr = new Uint8Array(len);
    for (let i=0;i<len;i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  // ---- Toast ----
  function showToast(msg, timeout=3000){
    toastEl.textContent = msg;
    toastEl.classList.remove('hidden');
    clearTimeout(showToast._t);
    showToast._t = setTimeout(()=> toastEl.classList.add('hidden'), timeout);
  }

  // ---- Google Identity Services (GSI) ----
  function initGSI(){
    window.handleCredentialResponse = async (resp) => {
      try {
        const idToken = resp.credential;
        // decode token payload quickly
        const payload = JSON.parse(atob(idToken.split('.')[1]));
        me = { userId: payload.sub, name: payload.name || payload.email, email: payload.email, idToken };
        profileName.textContent = me.name;
        profileEmail.textContent = me.email;
        gsiButtonDiv.style.display = 'none';
        signedInDiv.classList.remove('hidden');
        // Load or create keypair
        await ensureKeypairForMe();
        // register public key
        await registerPublicKey();
        // load user list and start polling
        await refreshUsers();
        startPolling();
        showToast('Signed in as ' + (me.name || me.email));
      } catch (e){
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
  async function ensureKeypairForMe(){
    if (!me) throw new Error('No user');
    // Try load record from IndexedDB
    const rec = await loadKeyRecord(me.userId);
    if (rec) {
      // if encrypted with passphrase, prompt for passphrase
      if (rec.encryptedWithPassphrase) {
        let tries = 0;
        let ok = false;
        while (!ok && tries < 3) {
          const pass = prompt('Enter your passphrase to unlock your private key (or Cancel to skip):');
          if (!pass) {
            // user cancelled — treat as no key
            break;
          }
          try {
            const privU8 = await decryptPrivateKeyWithPassphrase(rec, pass);
            myKeyPair = {
              privateKey: privU8,
              publicKey: sodiumLib.crypto_scalarmult_base(privU8) // derive public from private
            };
            ok = true;
            break;
          } catch (e) {
            tries++;
            alert('Incorrect passphrase. Try again.');
          }
        }
        if (!ok && !myKeyPair) {
          // user didn't unlock; offer to import or create new keypair (loses ability to read old messages)
          if (confirm('Could not unlock key. Would you like to import a key file or create a new key (creating new key will lose access to messages encrypted to old key)?')) {
            // user can import via UI button, or create new key
            await createNewKeypairFlow();
          } else {
            // create new keypair
            await createNewKeypairFlow();
          }
        }
      } else {
        // raw key stored
        myKeyPair = {
          privateKey: rawPrivateKeyFromRecord(rec),
          publicKey: base64ToUint8Array(rec.publicKeyBase64 || arrayBufferToBase64(sodiumLib.crypto_scalarmult_base(rawPrivateKeyFromRecord(rec)).buffer))
        };
      }
    } else {
      // no key record found — create new keypair
      await createNewKeypairFlow();
    }
  }

  async function createNewKeypairFlow(){
    const kp = sodiumLib.crypto_kx_keypair(); // gives publicKey, privateKey
    myKeyPair = { publicKey: kp.publicKey, privateKey: kp.privateKey };
    // Ask user if they want to protect private key with a passphrase
    const wantPass = confirm('Protect private key with a passphrase? Recommended. Click OK to set a passphrase, Cancel to store locally (less secure).');
    if (wantPass) {
      let pass = null;
      while (!pass) {
        pass = prompt('Choose a passphrase to protect your private key. Remember it—we cannot recover it for you.');
        if (!pass) { if (!confirm('No passphrase set. Store key unencrypted?')) continue; else break; }
      }
      if (pass) {
        const rec = await encryptPrivateKeyWithPassphrase(myKeyPair.privateKey, pass);
        // store also publicKey for convenience
        rec.publicKeyBase64 = arrayBufferToBase64(myKeyPair.publicKey.buffer);
        await saveKeyEncrypted(me.userId, rec);
      } else {
        // store raw (not recommended)
        const rec = recordFromRawPrivateKey(myKeyPair.privateKey);
        rec.publicKeyBase64 = arrayBufferToBase64(myKeyPair.publicKey.buffer);
        await saveKeyEncrypted(me.userId, rec);
      }
    } else {
      // store raw
      const rec = recordFromRawPrivateKey(myKeyPair.privateKey);
      rec.publicKeyBase64 = arrayBufferToBase64(myKeyPair.publicKey.buffer);
      await saveKeyEncrypted(me.userId, rec);
    }
  }

  async function registerPublicKey(){
    // upload public key to API (Apps Script upsert)
    const pkB64 = arrayBufferToBase64(myKeyPair.publicKey.buffer);
    const body = { idToken: me.idToken, publicKeyBase64: pkB64, name: me.name, email: me.email };
    try {
      const r = await fetch(API_BASE, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
      const j = await r.json();
      if (j.ok) return true;
      console.warn('registerPublicKey response', j);
      return false;
    } catch (e) {
      console.warn('registerPublicKey error', e);
      return false;
    }
  }

  // ---- Users list ----
  async function refreshUsers(){
    usersDiv.textContent = 'Loading...';
    try {
      const r = await fetch(API_BASE + '?action=getUsers');
      const j = await r.json();
      users = (j.users || []).filter(u => u.userId !== (me && me.userId));
      renderUsers();
    } catch (e) {
      usersDiv.textContent = 'Failed to load users';
      console.error(e);
    }
  }

  function renderUsers(){
    usersDiv.innerHTML = '';
    if (!users.length) { usersDiv.textContent = 'No users yet'; return; }
    users.forEach(u => {
      const el = document.createElement('div');
      el.className = 'user-item' + (selectedUser && selectedUser.userId === u.userId ? ' active' : '');
      el.innerHTML = `<div style="flex:1"><div class="name">${escapeHtml(u.name || u.email || u.userId)}</div><div class="email">${escapeHtml(u.email||'')}</div></div>`;
      el.onclick = () => { selectedUser = u; chatHeader.textContent = 'Chat with: ' + (u.name||u.email); messagesDiv.innerHTML=''; lastPollISO = new Date(0).toISOString(); };
      usersDiv.appendChild(el);
    });
  }

  // ---- Send message ----
  sendBtn.onclick = sendMessage;
  msgInput.onkeydown = (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) sendMessage(); };

  async function sendMessage(){
    const text = msgInput.value.trim();
    if (!text) return;
    if (!me || !myKeyPair || !selectedUser) { showToast('Sign in and select a user first'); return; }
    // compute shared secret: X25519(private, recipientPublic)
    const recipientPub = base64ToUint8Array(selectedUser.publicKeyBase64);
    const shared = sodiumLib.crypto_scalarmult(myKeyPair.privateKey, recipientPub); // Uint8Array
    // per-message salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = arrayBufferToBase64(salt.buffer);
    // msg id
    const msgId = 'm_' + Date.now() + '_' + Math.floor(Math.random()*100000);
    // derive AES key via HKDF
    const infoStr = `${me.userId}|${selectedUser.userId}|${msgId}`;
    const aesKey = await hkdfImport(shared, salt, infoStr);
    // encrypt
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aadStr = `${me.userId}|${selectedUser.userId}|${msgId}`;
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aadStr) }, aesKey, enc.encode(text));
    // build payload
    const payload = {
      idToken: me.idToken,
      action: 'postMessage',
      toUserId: selectedUser.userId,
      ciphertextBase64: arrayBufferToBase64(ct),
      ivBase64: arrayBufferToBase64(iv.buffer),
      saltBase64: saltB64,
      aad: aadStr,
      msgId: msgId
    };
    // optimistic UI
    appendMessage({ me: true, text, createdAt: new Date().toISOString() });
    msgInput.value = '';
    try {
      const r = await fetch(API_BASE, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
      const j = await r.json();
      if (!j.ok) showToast('Send failed');
    } catch (e) {
      console.error(e);
      showToast('Send failed (network)');
    }
  }

  function appendMessage({ me: isMe, text, createdAt }){
    const div = document.createElement('div');
    div.className = 'msg' + (isMe ? ' me' : '');
    const meta = document.createElement('div'); meta.className = 'meta'; meta.textContent = (isMe ? 'Me' : (selectedUser? selectedUser.name : 'Other')) + ' • ' + (new Date(createdAt)).toLocaleString();
    const body = document.createElement('div'); body.textContent = text;
    div.appendChild(meta); div.appendChild(body);
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }

  // ---- Polling for messages ----
  async function pollOnce(){
    if (!me) return;
    try {
      const url = `${API_BASE}?action=getMessages&toUserId=${encodeURIComponent(me.userId)}&since=${encodeURIComponent(lastPollISO)}&idToken=${encodeURIComponent(me.idToken)}`;
      const r = await fetch(url);
      const j = await r.json();
      if (j.messages && j.messages.length) {
        lastPollISO = new Date().toISOString();
        for (const m of j.messages) {
          // find sender in our users cache
          let sender = users.find(u => u.userId === m.fromUserId);
          if (!sender) {
            // reload users to try to find sender
            await refreshUsers();
            sender = users.find(u => u.userId === m.fromUserId) || { userId: m.fromUserId, name: m.fromUserId, publicKeyBase64: null };
          }
          // derive shared secret: X25519(myPrivate, senderPublic)
          if (!sender.publicKeyBase64) { console.warn('No public key for sender', m.fromUserId); continue; }
          const senderPub = base64ToUint8Array(sender.publicKeyBase64);
          const shared = sodiumLib.crypto_scalarmult(myKeyPair.privateKey, senderPub);
          // derive AES key using salt stored per message
          const salt = base64ToUint8Array(m.saltBase64);
          const aesKey = await hkdfImport(shared, salt, `${m.fromUserId}|${m.toUserId}|${m.msgId}`);
          // decrypt
          try {
            const iv = base64ToUint8Array(m.ivBase64);
            const ct = base64ToUint8Array(m.ciphertextBase64);
            const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(m.aad) }, aesKey, ct);
            const text = dec.decode(plainBuf);
            // only display if message is from selected user (or show toast)
            if (selectedUser && selectedUser.userId === m.fromUserId) {
              appendMessage({ me: false, text, createdAt: m.createdAt });
            } else {
              showToast(`New message from ${sender.name || sender.userId}`);
            }
          } catch (e) {
            console.warn('Decrypt failed for msg', m.msgId, e);
          }
        }
      }
    } catch (e) {
      console.warn('poll error', e);
    }
  }

  function startPolling(){
    if (polling) return;
    polling = true;
    (async function loop(){
      while (polling) {
        try { await pollOnce(); } catch(e){ console.warn(e); }
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
      }
    })();
  }

  function stopPolling(){ polling = false; }

  // ---- HKDF deriveKey helper (Web Crypto) ----
  async function hkdfImport(sharedUint8Array, saltUint8Array, infoStr){
    // import raw shared secret as HKDF base
    const ikm = sharedUint8Array.buffer ? sharedUint8Array.buffer : sharedUint8Array;
    const salt = saltUint8Array.buffer ? saltUint8Array.buffer : saltUint8Array;
    const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
    const derivedKey = await crypto.subtle.deriveKey({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt,
      info: enc.encode(infoStr || '')
    }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
    return derivedKey;
  }

  // ---- Export / Import private key (encrypted file) ----
  exportKeyBtn.onclick = async () => {
    if (!me) return showToast('Sign in first');
    const rec = await loadKeyRecord(me.userId);
    if (!rec) return showToast('No key to export');
    // Download JSON file
    const blob = new Blob([JSON.stringify(rec)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `chat-key-${me.userId}.json`; document.body.appendChild(a); a.click(); a.remove();
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
      try { rec = JSON.parse(text); } catch (e) { return showToast('Invalid key file'); }
      // store in IndexedDB under current userId
      if (!me) { return showToast('Sign in first to import key'); }
      await saveKeyEncrypted(me.userId, rec);
      showToast('Key imported. Reloading keys...');
      await ensureKeypairForMe();
    };
    input.click();
  };

  // ---- Sign out ----
  signOutBtn.onclick = () => {
    // Clear in-memory, show sign-in UI again
    me = null; myKeyPair = null; selectedUser = null;
    signedInDiv.classList.add('hidden');
    gsiButtonDiv.style.display = 'block';
    messagesDiv.innerHTML = ''; usersDiv.innerHTML = '';
    stopPolling();
    google.accounts.id.disableAutoSelect();
    showToast('Signed out');
  };

  // ---- Utility: escape HTML ----
  function escapeHtml(s){ if(!s) return ''; return s.replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }

  // ---- Utility: base64 conversions already above; include small helpers for typed arrays ----
  // (arrayBufferToBase64 and base64ToUint8Array defined earlier in this file scope)

  // ---- Start GSI and initial refresh ----
  initGSI();
  // initial users fetch (public endpoint)
  refreshUsers();

})();
