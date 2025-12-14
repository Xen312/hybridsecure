import express from "express";
import http from "http";
import WebSocket, { WebSocketServer } from "ws";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { OAuth2Client } from "google-auth-library";
import path from "path";
import { fileURLToPath } from "url";

import {
  getUserByGoogleId,
  createUser,
  listUsers,
  getMessages,
  saveMessage,
  logUserKeys,
  logChatSecret,
  logPlaintextMessage,
  logEncryptedMessage,
  logNetworkTraffic
} from "./sheets.js";

import {
  generateX25519KeyPair,
  computeSharedSecret,
  deriveAESKey,
  encryptAESGCM,
  decryptAESGCM
} from "./crypto.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/* ================= GOOGLE AUTH ================= */

const oauth = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

app.get("/auth/google", (req, res) => {
  res.redirect(
    oauth.generateAuthUrl({
      scope: ["profile", "email"],
      prompt: "select_account"
    })
  );
});

app.get("/auth/google/callback", async (req, res) => {
  try {
    const { tokens } = await oauth.getToken(req.query.code);

    const ticket = await oauth.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    res.cookie("google_id", payload.sub, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 1000 * 60 * 60 * 24
    });

    res.redirect("/");
  } catch (err) {
    console.error("AUTH ERROR:", err);
    res.status(500).send("Authentication failed");
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("google_id", {
    httpOnly: true,
    sameSite: "lax",
    path: "/"
  });
  res.redirect("/");
});

/* ================= AUTH API ================= */

const userKeys = new Map();
const chatKeys = new Map();

async function ensureUserKeys(google_id, username = "unknown") {
  if (!userKeys.has(google_id)) {
    const kp = generateX25519KeyPair();
    userKeys.set(google_id, kp);

    await logUserKeys({
      google_id,
      username,
      privateKey: kp.privateKey,
      publicKey: kp.publicKey
    });
  }
  return userKeys.get(google_id);
}

app.get("/me", async (req, res) => {
  const id = req.cookies.google_id;
  if (!id) return res.json({ error: "not logged in" });

  const user = await getUserByGoogleId(id);
  if (!user) return res.json({ error: "user missing" });

  await ensureUserKeys(id, user.username);
  res.json(user);
});

app.post("/username", async (req, res) => {
  const id = req.cookies.google_id;
  if (!id) return res.status(401).json({ error: "unauthorized" });

  await createUser({
    google_id: id,
    username: req.body.username,
    picture: req.body.picture,
    email: req.body.email
  });

  res.json({ success: true });
});

app.get("/users", async (req, res) => {
  const me = req.cookies.google_id;
  if (!me) return res.json([]);

  const users = await listUsers();
  res.json(users.filter(u => u.google_id !== me));
});

app.get("/messages", async (req, res) => {
  res.json(await getMessages(req.query.chat_id));
});

/* ================= WEBSOCKET ================= */

wss.on("connection", ws => {
  ws.on("message", async raw => {
    const msg = JSON.parse(raw);

    if (msg.type === "join") {
      ws.chat_id = msg.chat_id;

      if (!chatKeys.has(msg.chat_id)) {
        const [a, b] = msg.chat_id.split("_");

        const sa = await ensureUserKeys(a);
        const sb = await ensureUserKeys(b);

        const secret = computeSharedSecret(sa.privateKey, sb.publicKey);
        const aesKey = deriveAESKey(secret, msg.chat_id);

        chatKeys.set(msg.chat_id, aesKey);

        await logChatSecret({
          chat_id: msg.chat_id,
          user_a: a,
          user_b: b,
          sharedSecret: secret.toString("base64"),
          aesKey: aesKey.toString("base64")
        });
      }
      return;
    }

    const aesKey = chatKeys.get(msg.chat_id);
    const encrypted = encryptAESGCM(aesKey, msg.text);

    await logPlaintextMessage({
      chat_id: msg.chat_id,
      sender: msg.sender_id,
      plaintext: msg.text
    });

    await logEncryptedMessage({
      chat_id: msg.chat_id,
      sender: msg.sender_id,
      ...encrypted
    });

    await logNetworkTraffic({
      direction: "client→server",
      payload: encrypted
    });

    const decrypted = decryptAESGCM(
      aesKey,
      encrypted.iv,
      encrypted.ciphertext,
      encrypted.authTag
    );

    const finalMsg = { ...msg, text: decrypted };
    await saveMessage(finalMsg);

    wss.clients.forEach(c => {
      if (c.readyState === WebSocket.OPEN && c.chat_id === msg.chat_id) {
        c.send(JSON.stringify({ type: "message", message: finalMsg }));
      }
    });
  });
});

server.listen(process.env.PORT || 8080, () =>
  console.log("Server running on http://localhost:8080")
);
