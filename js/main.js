// app.js — main application
import { csvToObjects, base64UrlToU8, u8ToBase64Url } from './utils.js';
import { initSodium, computeShared, deriveAesKey, aesEncrypt, aesDecrypt } from './crypto.js';

/////////////////////
// PLACEHOLDERS — EDIT THESE
/////////////////////
const FORM_ACTION_URL = "/* REPLACE_ME: https://docs.google.com/forms/d/e/<FORM_ID>/formResponse */";
// Map your form fields: replace these entry.xxxxx with your form's entry IDs
const ENTRY_ROOMID = "/* REPLACE_ME: entry.111111111 */";
const ENTRY_USERNAME = "/* REPLACE_ME: entry.222222222 */";
const ENTRY_MSGTYPE = "/* REPLACE_ME: entry.333333333 */";
const ENTRY_SENDERPUB = "/* REPLACE_ME: entry.444444444 */";
const ENTRY_RECIPIENT = "/* REPLACE_ME: entry.555555555 */";
const ENTRY_CIPHERTEXT = "/* REPLACE_ME: entry.666666666 */";
const ENTRY_IV = "/* REPLACE_ME: entry.777777777 */";
const ENTRY_SALT = "/* REPLACE_ME: entry.888888888 */";
const ENTRY_HKDFINFO = "/* REPLACE_ME: entry.999999999 */";
const ENTRY_TIMESTAMP = "/* REPLACE_ME: entry.000000000 */";

const SHEET_CSV_URL = "/* REPLACE_ME: https://docs.google.com/spreadsheets/d/e/<SHEET_ID>/pub?gid=0&single=true&output=csv */";
/////////////////////

let sodium;
let kp = null;
let me = { username: null };
let members = {}; // username -> {pub}

const $ = id => document.getElementById(id);

function syslog(msg) {
  console.log(new Date().toISOString(), msg);
}

// UI wiring
async function init() {
  sodium = await initSodium();
  syslog("libsodium ready");
  $('btnClaim').addEventListener('click', claim);
  $('btnGenKeys').addEventListener('click', genKeys);
  $('send').addEventListener('click', sendMessage);
  setInterval(pollSheet, 3000);
}

function addMemberToUI(name, pub) {
  members[name] = { pub };
  const mdiv = document.createElement('div'); mdiv.textContent = name;
  $('members').appendChild(mdiv);
  const sel = $('recipient'); if (![...sel.options].some(o=>o.value===name)) {
    const opt = document.createElement('option'); opt.value = name; opt.text = name; sel.appendChild(opt);
  }
}

function addChat(who, text, meFlag=false) {
  const box = $('chatbox');
  const d = document.createElement('div'); d.className = 'message ' + (meFlag?'me':'other');
  d.innerHTML = `<div><strong>${who}</strong></div><div>${text}</div>`;
  box.appendChild(d); box.scrollTop = box.scrollHeight;
}

// Generate ephemeral keypair
function genKeys(){
  const k = sodium.crypto_kx_keypair();
  kp = { publicKey: k.publicKey, privateKey: k.privateKey };
  syslog("Generated keys, pub: " + u8ToBase64Url(kp.publicKey).slice(0,20)+'...');
  if (me.username) postPubkey();
}

// Claim username and post announce + pubkey
async function claim(){
  const name = $('username').value.trim();
  const room = $('roomId').value.trim();
  if (!name) { alert("Enter username"); return; }
  me.username = name;
  // quick uniqueness: fetch CSV and check
  try {
    const res = await fetch(SHEET_CSV_URL); const txt = await res.text();
    const rows = csvToObjects(txt);
    const inUse = rows.some(r => r.roomId===room && r.username===name && ((Date.now() - new Date(r.Timestamp).getTime()) < 10*60*1000));
    if (inUse) { alert("Username seems in use in this room; pick another."); return; }
  } catch(e){ console.warn("CSV check failed", e); }
  if (!kp) genKeys();
  // post announce and pubkey
  await postForm({
    [ENTRY_ROOMID]: room,
    [ENTRY_USERNAME]: me.username,
    [ENTRY_MSGTYPE]: "announce",
    [ENTRY_SENDERPUB]: u8ToBase64Url(kp.publicKey),
    [ENTRY_TIMESTAMP]: new Date().toISOString()
  });
  await postPubkey();
  addMemberToUI(me.username, u8ToBase64Url(kp.publicKey));
}

// Post pubkey row
async function postPubkey(){
  const room = $('roomId').value.trim();
  if (!kp) return;
  await postForm({
    [ENTRY_ROOMID]: room,
    [ENTRY_USERNAME]: me.username,
    [ENTRY_MSGTYPE]: "pubkey",
    [ENTRY_SENDERPUB]: u8ToBase64Url(kp.publicKey),
    [ENTRY_TIMESTAMP]: new Date().toISOString()
  });
}

// Generic form POST wrapper
async function postForm(obj) {
  const fd = new FormData();
  for (const k in obj) fd.append(k, obj[k]);
  // no-cors; response opaque
  await fetch(FORM_ACTION_URL, { method: 'POST', mode: 'no-cors', body: fd });
  syslog("Posted form row: " + JSON.stringify(Object.keys(obj)));
}

// Poll published sheet CSV to discover pubkeys and messages
let lastLen = 0;
async function pollSheet(){
  try {
    const res = await fetch(SHEET_CSV_URL);
    if(!res.ok) return;
    const txt = await res.text();
    const rows = csvToObjects(txt);
    // process rows from lastLen onwards
    for (let i = lastLen; i < rows.length; i++) {
      const r = rows[i];
      if (r.roomId !== $('roomId').value.trim()) continue;
      const type = (r.msgType||'').trim();
      if (type === 'pubkey' || type === 'announce') {
        if (r.username && r.senderPub) addMemberToUI(r.username, r.senderPub);
      } else if (type === 'msg') {
        const recipient = (r.recipient||'').trim();
        if (recipient !== '*' && recipient !== me.username) continue;
        // attempt decryption
        if (!kp) { syslog('no keys'); continue; }
        try {
          const theirPk = base64UrlToU8(r.senderPub);
          const shared = computeShared(sodium, kp.privateKey, theirPk);
          const salt = base64UrlToU8(r.salt);
          const aesKey = await deriveAesKey(shared, salt, r.hkdfInfo || `HYBRID|${r.roomId}|${r.username}|${recipient}`);
          const iv = base64UrlToU8(r.iv);
          const ct = base64UrlToU8(r.ciphertext);
          const ad = new TextEncoder().encode(`${r.roomId}|${r.username}|${recipient}|${r.Timestamp||r.timestamp||''}`);
          const pt = await aesDecrypt(aesKey, iv, ad, ct);
          addChat(r.username, pt, false);
        } catch (e) {
          syslog("decrypt failed for row: " + e.message);
        }
      }
    }
    lastLen = rows.length;
  } catch (e) { console.warn("poll error", e); }
}

// Send message
async function sendMessage(){
  const text = $('message').value.trim();
  if (!text) return;
  if (!me.username) { alert("Claim username first"); return; }
  const recipient = $('recipient').value;
  if (recipient === me.username) { alert("Choose another recipient"); return; }
  if (!members[recipient] || !members[recipient].pub) { alert("Recipient pubkey unknown"); return; }
  try {
    const theirPk = base64UrlToU8(members[recipient].pub);
    const shared = computeShared(sodium, kp.privateKey, theirPk);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const info = `HYBRID|${$('roomId').value.trim()}|${me.username}|${recipient}`;
    const aesKey = await deriveAesKey(shared, salt, info);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ad = new TextEncoder().encode(`${$('roomId').value.trim()}|${me.username}|${recipient}|${new Date().toISOString()}`);
    const ctU8 = await aesEncrypt(aesKey, iv, ad, text);
    // post to form
    const payload = {
      [ENTRY_ROOMID]: $('roomId').value.trim(),
      [ENTRY_USERNAME]: me.username,
      [ENTRY_MSGTYPE]: "msg",
      [ENTRY_SENDERPUB]: u8ToBase64Url(kp.publicKey),
      [ENTRY_RECIPIENT]: recipient,
      [ENTRY_CIPHERTEXT]: u8ToBase64Url(ctU8),
      [ENTRY_IV]: u8ToBase64Url(iv),
      [ENTRY_SALT]: u8ToBase64Url(salt),
      [ENTRY_HKDFINFO]: info,
      [ENTRY_TIMESTAMP]: new Date().toISOString()
    };
    await postForm(payload);
    addChat('me', text, true);
    $('message').value = '';
  } catch (e) { alert("Send failed: " + e.message); }
}

window.addEventListener('load', init);
