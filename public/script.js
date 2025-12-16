let currentUser = null;
let ws = null;
let selectedUser = null;

/* ===== DOM ELEMENTS (MATCH YOUR index.html) ===== */
const loginScreen = document.getElementById("login-screen");
const usernameScreen = document.getElementById("username-screen");
const appScreen = document.getElementById("app");

const googleLoginBtn = document.getElementById("googleLoginBtn");
const logoutBtn = document.getElementById("logoutBtn");

const usernameInput = document.getElementById("usernameInput");
const setUsernameBtn = document.getElementById("setUsernameBtn");
const usernameError = document.getElementById("usernameError");

const userList = document.getElementById("userList");
const searchInput = document.getElementById("searchInput");

const myPic = document.getElementById("myPic");
const myName = document.getElementById("myName");

const chatPic = document.getElementById("chatPic");
const chatName = document.getElementById("chatName");

const messagesEl = document.getElementById("messages");
const messageInput = document.getElementById("messageInput");
const sendBtn = document.getElementById("sendBtn");

/* ===== UI HELPERS ===== */
function showLogin() {
  loginScreen.classList.remove("hidden");
  usernameScreen.classList.add("hidden");
  appScreen.classList.add("hidden");
}

function showUsername() {
  loginScreen.classList.add("hidden");
  usernameScreen.classList.remove("hidden");
  appScreen.classList.add("hidden");
}

function showApp() {
  loginScreen.classList.add("hidden");
  usernameScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");
}

/* ===== AUTH CHECK (SINGLE SOURCE OF TRUTH) ===== */
async function checkAuth() {
  try {
    const res = await fetch("/me");
    const data = await res.json();

    if (data.error) {
      showLogin();
      return;
    }

    currentUser = data;

    if (!currentUser.username) {
      showUsername();
      return;
    }

    myName.textContent = currentUser.username;
    myPic.src = currentUser.picture;

    showApp();
    await loadUsers();
    setupWebSocket();

  } catch (err) {
    console.error("Auth check failed:", err);
    showLogin();
  }
}

document.addEventListener("DOMContentLoaded", checkAuth);

/* ===== LOGIN / LOGOUT ===== */
googleLoginBtn.onclick = async () => {
  try {
    const credential = window.googleCredential; // or however you store it

    const res = await fetch("/auth/google", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ credential })
    });

    const data = await res.json();

    if (!data.success) {
      alert("Google login failed");
      return;
    }

    // Stay on "/", do NOT redirect
    initApp(data.user);

  } catch (err) {
    console.error(err);
    alert("Login error");
  }
};


logoutBtn.onclick = () => {
  window.location.href = "/logout";
};

/* ===== USERNAME SETUP ===== */
setUsernameBtn.onclick = async () => {
  const username = usernameInput.value.trim();
  if (!username) return;

  const res = await fetch("/username", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username,
      picture: currentUser.picture,
      email: currentUser.email
    })
  });

  const data = await res.json();
  if (data.error) {
    usernameError.textContent = data.error;
    return;
  }

  location.reload();
};

/* ===== USERS ===== */
async function loadUsers() {
  const res = await fetch("/users");
  const users = await res.json();

  userList.innerHTML = "";

  users.forEach(user => {
    const div = document.createElement("div");
    div.className = "user-item";

    const img = document.createElement("img");
    img.src = user.picture;
    img.className = "user-avatar";
    img.className = "pfp";

    const name = document.createElement("span");
    name.textContent = user.username;

    div.appendChild(img);
    div.appendChild(name);

    div.onclick = () => openChat(user);
    userList.appendChild(div);
  });
}

/* ===== CHAT ===== */
function createChatId(a, b) {
  return [a, b].sort().join("_");
}

async function openChat(user) {
  selectedUser = user;

  chatName.textContent = user.username;
  chatPic.src = user.picture;

  messagesEl.innerHTML = "";

  const chat_id = createChatId(currentUser.google_id, user.google_id);
  const history = await (await fetch(`/messages?chat_id=${chat_id}`)).json();

  history.forEach(msg => addMessage(msg, msg.sender_id === currentUser.google_id));

  ws.send(JSON.stringify({ type: "join", chat_id }));
  ws.chat_id = chat_id;
}

function addMessage(msg, mine) {
  const bubble = document.createElement("div");
  bubble.className = mine ? "bubble mine" : "bubble";
  bubble.innerHTML = `
    <div class="bubble-name">${msg.username}</div>
    <div>${msg.text}</div>
  `;
  messagesEl.appendChild(bubble);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

/* ===== WEBSOCKET ===== */
function setupWebSocket() {
  ws = new WebSocket(`ws://${location.host}`);

  ws.onmessage = e => {
    const data = JSON.parse(e.data);
    if (data.type === "message") {
      addMessage(
        data.message,
        data.message.sender_id === currentUser.google_id
      );
    }
  };
}

/* ===== SEND MESSAGE ===== */
sendBtn.onclick = sendMessage;
messageInput.onkeydown = e => {
  if (e.key === "Enter") sendMessage();
};

function sendMessage() {
  if (!ws?.chat_id || !messageInput.value.trim()) return;

  ws.send(JSON.stringify({
    chat_id: ws.chat_id,
    sender_id: currentUser.google_id,
    username: currentUser.username,
    picture: currentUser.picture,
    text: messageInput.value,
    timestamp: Date.now()
  }));

  messageInput.value = "";
}
