/* =======================
   IMPORTS
======================= */
import express from "express";
import http from "http";
import { WebSocketServer } from "ws";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { OAuth2Client } from "google-auth-library";

/* ===== CRYPTO ===== */
import {
  generateX25519KeyPair,
  computeSharedSecret,
  deriveAESKeyHKDF,
  encryptAESGCM
} from "./crypto.js";

/* ===== GOOGLE SHEETS ===== */
import {
  createUser,
  getUserByGoogleId,
  listUsers,
  saveMessage,
  getMessages,
  logUserKeys,
  logChatSecret,
  logEncryptedMessage,
  logPlaintextMessage,
  logNetworkTraffic
} from "./sheets.js";

dotenv.config();

/* =======================
   PATH FIX
======================= */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* =======================
   CONSTANTS
======================= */
const PORT = process.env.PORT || 8080;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

/* =======================
   APP SETUP
======================= */
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

/* =======================
   IN-MEMORY STORAGE
======================= */
const userKeys = new Map(); // google_id -> keypair

/* =======================
   MIDDLEWARE
======================= */
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/* =======================
   ROUTES
======================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* ---------- GOOGLE LOGIN ---------- */
app.post("/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const google_id = payload.sub;

    let user = await getUserByGoogleId(google_id);

    if (!user) {
      await createUser({
        google_id,
        username: payload.name,
        picture: payload.picture,
        email: payload.email
      });

      user = await getUserByGoogleId(google_id);
    }

    if (!userKeys.has(google_id)) {
      const kp = generateX25519KeyPair();
      userKeys.set(google_id, kp);

      await logUserKeys({
        google_id,
        username: user.username,
        privateKey: kp.privateKey,
        publicKey: kp.publicKey
      });
    }

    res.cookie("google_id", google_id, {
      httpOnly: true,
      sameSite: "lax"
    });

    res.json({ success: true, user });

  } catch (err) {
    console.error(err);
    res.status(401).json({ error: "Google auth failed" });
  }
});

/* ---------- CURRENT USER ---------- */
app.get("/me", async (req, res) => {
  const google_id = req.cookies.google_id;
  if (!google_id) return res.json(null);

  const user = await getUserByGoogleId(google_id);
  res.json(user);
});


app.get("/users", async (req, res) => {
  const google_id = req.cookies.google_id;
  if (!google_id) return res.status(401).json([]);

  const users = await listUsers();
  res.json(users.filter(u => u.google_id !== google_id));
});


/* ---------- CHAT HISTORY ---------- */
app.get("/messages", async (req, res) => {
  const { chat_id } = req.query;
  if (!chat_id) return res.json([]);
  res.json(await getMessages(chat_id));
});

/* =======================
   WEBSOCKET
======================= */
wss.on("connection", socket => {
  socket.on("message", async raw => {
    const msg = JSON.parse(raw);

    if (msg.type === "join") {
      socket.chat_id = msg.chat_id;
      socket.user_id = msg.user_id;
      return;
    }

    const { chat_id, sender_id, username, text, timestamp } = msg;

    /* ===== LOG PLAINTEXT ===== */
    await logPlaintextMessage({
      chat_id,
      sender: sender_id,
      plaintext: text,
      timestamp
    });

    /* ===== CRYPTO ===== */
    const [a, b] = chat_id.split("_");
    const receiver_id = sender_id === a ? b : a;
    
    // Ensure sender key exists at WS-time
    if (!userKeys.has(sender_id)) {
      const user = await getUserByGoogleId(sender_id);
      if (user) {
        const kp = generateX25519KeyPair();
        userKeys.set(sender_id, kp);

        await logUserKeys({
          google_id: sender_id,
          username: user.username,
          privateKey: kp.privateKey,
          publicKey: kp.publicKey
        });
      }
    }

    const senderKey = userKeys.get(sender_id);
    const receiverKey = userKeys.get(receiver_id);

    if (senderKey && receiverKey) {
      const sharedSecret = computeSharedSecret(
        senderKey.privateKey,
        receiverKey.publicKey
      );

      const aesKey = deriveAESKeyHKDF(sharedSecret, chat_id);

      // Log chat secret ONCE per chat
      if (!global.chatSecretsLogged) {
        global.chatSecretsLogged = new Set();
      }

      if (!global.chatSecretsLogged.has(chat_id)) {

        const [user_a, user_b] = chat_id.split("_");

        console.log("logChatSecret reached");
        await logChatSecret({
          chat_id,
          user_a,
          user_b,
          sharedSecret: sharedSecret.toString("base64"),
          aesKey: aesKey.toString("base64")
        });

        socket.chatSecretLogged = true;
      }

      const encrypted = encryptAESGCM(aesKey, text);

      console.log("logEncryptedMessage reached");
      await logEncryptedMessage({
        chat_id,
        sender: sender_id,
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
        authTag: encrypted.authTag,
        timestamp
      });

      await logNetworkTraffic({
        direction: "websocket",
        payload: encrypted.ciphertext
      });
    }

    /* ===== SAVE MESSAGE ===== */
    await saveMessage(msg);

    /* ===== BROADCAST ===== */
    wss.clients.forEach(client => {
      if (
        client.readyState === client.OPEN &&
        client.chat_id === chat_id
      ) {
        client.send(JSON.stringify({
          type: "message",
          message: msg
        }));
      }
    });
  });
});

/* =======================
   START SERVER
======================= */
server.listen(PORT, () => {
  console.log(` Server running on port http://localhost:${PORT}`);
});
