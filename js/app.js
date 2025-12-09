// app.js — main demo app
import { csvToObjects, base64UrlToU8, u8ToBase64Url } from './utils.js';
import { initSodium, computeShared, deriveAesKey, aesEncrypt, aesDecrypt } from './crypto.js';

// ---------- EMBEDDED CONFIG (already set) ----------
const GOOGLE_CLIENT_ID = "90846963850-o4892dm0jigrefdu4c3h7ljb5qbotssd.apps.googleusercontent.com";

const FORM_ACTION_URL = "https://docs.google.com/forms/d/e/1e4Z1MJ-Dnfy5T1wwoCZkQWzRRdRu4QeuyVQ4WnIV_9w/formResponse";
const SHEET_CSV_URL = "https://docs.google.com/spreadsheets/d/e/1OsDl4n-jRbei3g-RbzoQDYmaJ-t8lC_kq1a2aQPK8EA/pub?gid=0&single=true&output=csv";

// entry map discovered from prefilled URL
const ENTRY = {
  roomId: "entry.813368284",
  username: "entry.1322484853",
  msgType: "entry.190129408",
  senderPub: "entry.1029978266",
  recipient: "entry.1469584366",
  ciphertext: "entry.1323185749",
  iv: "entry.1755657405",
  salt: "entry.1762232920",
  hkdfInfo: "entry.1836963219",
  timestamp: "entry.1352420177"
};
// ---------- end config ----------

let sodium;
let kp = null; // {publicKey, privateKey}
let me = { username: null, name:null, email:null, id:null };
let usersIndex = {}; // username -> {firstSeenRow,..., pub}
let friends = {}; // username -> {accepted:true}
let pendingRequests = []; // {from, timestamp}
let activeChat = null; // username

const $ = id => document.getElementById(id);

// utility: post to form
async function postForm(obj) {
  const fd = new FormData();
  for (const k in obj) fd.append(k, obj[k]);
  await fetch(FORM_ACTION_URL, { method: 'POST', mode: 'no-cors', body: fd });
}

// initialize: libsodium + Google Sign-In + UI hooks
async function init() {
  sodium = await initSodium();
  console.log("sodium ready");

  // Google Sign-In setup
  window.handleCredentialResponse = (resp) => {
    try {
      const payload = JSON.parse(atob(resp.credential.split(".")[1]));
      me.name = payload.name || payload.email;
      me.email = payload.email || "";
      me.id = payload.sub || payload.sub;
      $('displayName').textContent = me.name;
      $('displayEmail').textContent = me.email;
      $('username').value = me.name.replace(/\s+/g,'_').slice(0,20);
    } catch (e) { console.warn("signin parse failed", e); }
  };
  google.accounts.id.initialize({ client_id: GOOGLE_CLIENT_ID, callback: handleCredentialResponse, auto_select: false });
  google.accounts.id.renderButton(document.getElementById('signin-area'), { theme: 'outline', size: 'medium' });

  // UI hooks
  $('btnClaim').addEventListener('click', claimUsername);
  $('searchUser').addEventListener('input', onSearch);
  $('sendBtn').addEventListener('click', onSend);

  // poll sheet
  setInterval(pollSheet, 3000);
  // initial fetch
  await pollSheet();
  renderContacts();
}

async function claimUsername() {
  const desired = $('username').value.trim();
  if (!desired) { alert("Enter a username"); return; }
  // quick uniqueness check by scanning local usersIndex
  if (usersIndex[desired] && (usersIndex[desired].username !== me.username)) {
    alert("Username already taken — choose another");
    return;
  }
  me.username = desired;
  // generate ephemeral keypair
  generateKeys();
  // announce user: msgType = user_announce (we use hkdfInfo to carry google_id)
  await postForm({
    [ENTRY.roomId]: "global",
    [ENTRY.username]: me.username,
    [ENTRY.msgType]: "user_announce",
    [ENTRY.senderPub]: u8ToBase64Url(kp.publicKey),
    [ENTRY.hkdfInfo]: me.id || me.email || "unknown", // store google id lightly
    [ENTRY.timestamp]: new Date().toISOString()
  });
  // also post pubkey row (msgType pubkey)
  await postForm({
    [ENTRY.roomId]: "global",
    [ENTRY.username]: me.username,
    [ENTRY.msgType]: "pubkey",
    [ENTRY.senderPub]: u8ToBase64Url(kp.publicKey),
    [ENTRY.timestamp]: new Date().toISOString()
  });
  alert("Username claimed and announced");
  renderContacts();
}

// generate ephemeral keys using libsodium
function generateKeys(){
  const k = sodium.crypto_kx_keypair();
  kp = { publicKey: k.publicKey, privateKey: k.privateKey };
  console.log("generated keys", u8ToBase64Url(kp.publicKey).slice(0,16));
}

// Search users by prefix (local)
function onSearch(e) {
  const q = e.target.value.trim().toLowerCase();
  const results = Object.keys(usersIndex).filter(u => u.toLowerCase().includes(q) && u !== me.username);
  const div = $('searchResults'); div.innerHTML = '';
  for (const name of results.slice(0,20)) {
    const item = document.createElement('div'); item.className='userItem';
    item.innerHTML = `<span>${name}</span><div><button data-name="${name}" class="btn small">Add</button></div>`;
    div.appendChild(item);
    item.querySelector('button').addEventListener('click', ()=>sendFriendRequest(name));
  }
}

// send friend request (posts friend_request)
async function sendFriendRequest(target) {
  if (!me.username) { alert("Claim username first"); return; }
  await postForm({
    [ENTRY.roomId]: "global",
    [ENTRY.username]: me.username,
    [ENTRY.msgType]: "friend_request",
    [ENTRY.recipient]: target,
    [ENTRY.hkdfInfo]: me.id || me.email || "",
    [ENTRY.timestamp]: new Date().toISOString()
  });
  alert("Friend request sent to " + target);
}

// accept friend request (post friend_response with action accept)
async function respondFriendRequest(fromUser, action) {
  if (!me.username) return;
  await postForm({
    [ENTRY.roomId]: "global",
    [ENTRY.username]: me.username,
    [ENTRY.msgType]: "friend_response",
    [ENTRY.recipient]: fromUser,
    [ENTRY.hkdfInfo]: action, // "accept" or "decline" encoded in hkdfInfo field
    [ENTRY.timestamp]: new Date().toISOString()
  });
}

// start chat with friend (open chat UI)
function openChat(username) {
  activeChat = username;
  $('welcome').classList.add('hidden');
  $('chatWindow').classList.remove('hidden');
  $('chatHeader').textContent = "Chat with " + username;
  $('messages').innerHTML = '';
  // fetch message history from usersIndex (we will display decrypted messages as they come)
}

// send message to active chat
async function onSend() {
  const text = $('messageInput').value.trim();
  if (!text || !activeChat) return;
  const recipient = activeChat;
  // ensure we have their pubkey
  const rec = usersIndex[recipient];
  if (!rec || !rec.pub) { alert("Recipient pubkey unknown. Ask them to claim username."); return; }
  try {
    const theirPk = base64UrlToU8(rec.pub);
    const shared = computeShared(sodium, kp.privateKey, theirPk);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const info = `HYBRID|global|${me.username}|${recipient}`;
    const aesKey = await deriveAesKey(shared, salt, info);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ad = new TextEncoder().encode(`global|${me.username}|${recipient}|${new Date().toISOString()}`);
    const ctU8 = await aesEncrypt(aesKey, iv, ad, text);
    // post message
    await postForm({
      [ENTRY.roomId]: "global",
      [ENTRY.username]: me.username,
      [ENTRY.msgType]: "message",
      [ENTRY.senderPub]: u8ToBase64Url(kp.publicKey),
      [ENTRY.recipient]: recipient,
      [ENTRY.ciphertext]: u8ToBase64Url(ctU8),
      [ENTRY.iv]: u8ToBase64Url(iv),
      [ENTRY.salt]: u8ToBase64Url(salt),
      [ENTRY.hkdfInfo]: info,
      [ENTRY.timestamp]: new Date().toISOString()
    });
    displayMessage(me.username, text, true);
    $('messageInput').value = '';
  } catch (e) {
    console.error(e); alert("Send failed: " + e.message);
  }
}

// poll sheet and process rows
let lastRows = 0;
async function pollSheet() {
  try {
    const res = await fetch(SHEET_CSV_URL);
    if (!res.ok) return;
    const txt = await res.text();
    const rows = csvToObjects(txt);
    for (let i = lastRows; i < rows.length; i++) {
      handleRow(rows[i]);
    }
    lastRows = rows.length;
  } catch (e) { console.warn("poll error", e); }
}

function handleRow(row) {
  // Sheet headers: Timestamp then the form field labels (we used logical labels when creating the form)
  // Access fields safely—some headers may vary; fallback to common names
  const room = row.roomId || row['roomId'] || "";
  const type = (row.msgType || row['msgType'] || "").trim();
  const sender = (row.username || row['username'] || "").trim();
  if (!sender) return;

  if (type === "user_announce" || type === "pubkey") {
    const pub = row.senderPub || row['senderPub'] || "";
    if (pub) {
      if (!usersIndex[sender]) usersIndex[sender] = { username: sender, pub: pub, firstSeen: row.Timestamp || row.timestamp || new Date().toISOString() };
      else usersIndex[sender].pub = pub;
      renderContacts();
    }
  } else if (type === "friend_request") {
    const recipient = (row.recipient || row['recipient'] || "").trim();
    if (recipient === me.username) {
      pendingRequests.push({ from: sender, ts: row.Timestamp || row.timestamp || new Date().toISOString() });
      renderRequests();
    }
  } else if (type === "friend_response") {
    const to = (row.recipient || row['recipient'] || "").trim();
    const action = (row.hkdfInfo || row['hkdfInfo'] || "").trim(); // we encoded action here
    if (to === me.username && action === 'accept') {
      friends[sender] = { accepted: true };
      friends[me.username] = friends[me.username] || {};
      alert(sender + " accepted your friend request");
      renderContacts();
    }
  } else if (type === "message") {
    const recipient = (row.recipient || row['recipient'] || "").trim();
    if (recipient !== me.username && recipient !== '*') {
      // not for us
      return;
    }
    // attempt decrypt
    if (!kp) { console.warn("no keys, cannot decrypt"); return; }
    try {
      const theirPub = base64UrlToU8(row.senderPub || row['senderPub'] || "");
      const shared = computeShared(sodium, kp.privateKey, theirPub);
      const salt = base64UrlToU8(row.salt || row['salt'] || "");
      const info = row.hkdfInfo || row['hkdfInfo'] || `HYBRID|global|${row.username}|${recipient}`;
      deriveAesKey(shared, salt, info).then(async (aesKey) => {
        const iv = base64UrlToU8(row.iv || row['iv'] || "");
        const ct = base64UrlToU8(row.ciphertext || row['ciphertext'] || "");
        const ad = new TextEncoder().encode(`${room}|${row.username}|${recipient}|${row.Timestamp||row.timestamp||''}`);
        try {
          const pt = await aesDecrypt(aesKey, iv, ad, ct);
          displayMessage(row.username, pt, row.username === me.username);
        } catch (e) {
          console.warn("decrypt failed", e);
        }
      });
    } catch (e) { console.warn("decrypt error", e); }
  }
}

function renderContacts() {
  const div = $('contacts'); div.innerHTML = '';
  for (const name of Object.keys(usersIndex).sort()) {
    if (name === me.username) continue;
    const item = document.createElement('div'); item.className='userItem';
    const isFriend = !!friends[name];
    item.innerHTML = `<span>${name}</span><div>${isFriend?'<button class="btn small" data-name="'+name+'">Chat</button>':'<button class="btn small" data-name="'+name+'">Add</button>'}</div>`;
    div.appendChild(item);
    item.querySelector('button').addEventListener('click', (e)=>{
      const target = e.target.dataset.name;
      if (friends[target]) openChat(target);
      else sendFriendRequest(target);
    });
  }
}

function renderRequests() {
  const div = $('requests'); div.innerHTML = '';
  for (const r of pendingRequests) {
    const item = document.createElement('div'); item.className='userItem';
    item.innerHTML = `<span>${r.from}</span><div><button class="btn small accept" data-from="${r.from}">Accept</button></div>`;
    div.appendChild(item);
    item.querySelector('.accept').addEventListener('click', ()=>{
      respondFriendRequest(r.from, 'accept');
      friends[r.from] = { accepted: true };
      pendingRequests = pendingRequests.filter(x => x.from !== r.from);
      renderRequests(); renderContacts();
    });
  }
}

function displayMessage(who, text, meFlag=false) {
  const mdiv = document.createElement('div'); mdiv.className = 'msg ' + (meFlag? 'me':'other');
  mdiv.innerHTML = `<div><strong>${who}</strong></div><div>${text}</div>`;
  $('messages').appendChild(mdiv);
  $('messages').scrollTop = $('messages').scrollHeight;
}

function openChatUIWith(user) {
  openChat(user);
}

// start up
window.addEventListener('load', init);
