// sheets.js
import { google } from "googleapis";
import dotenv from "dotenv";
dotenv.config();

const auth = new google.auth.JWT(
  process.env.SERVICE_ACCOUNT_EMAIL,
  null,
  process.env.SERVICE_ACCOUNT_PRIVATE_KEY.replace(/\\n/g, "\n"),
  ["https://www.googleapis.com/auth/spreadsheets"]
);

const sheets = google.sheets({ version: "v4", auth });
const SPREADSHEET_ID = process.env.SPREADSHEET_ID;

/* ===== EXISTING CHAT STORAGE ===== */

export async function getUserByGoogleId(id) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SPREADSHEET_ID,
    range: "USERS!A2:D"
  });

  const rows = res.data.values || [];
  const r = rows.find(row => row[0] === id);
  if (!r) return null;

  return {
    google_id: r[0],
    username: r[1],
    picture: r[2],
    email: r[3]
  };
}

export async function createUser(user) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "USERS!A2:D",
    valueInputOption: "RAW",
    requestBody: {
      values: [[user.google_id, user.username, user.picture, user.email]]
    }
  });
}

export async function getMessages(chatId) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SPREADSHEET_ID,
    range: "MESSAGES!A2:F"
  });

  const rows = res.data.values || [];
  return rows
    .filter(r => r[0] === chatId)
    .map(r => ({
      chat_id: r[0],
      sender_id: r[1],
      username: r[2],
      picture: r[3],
      text: r[4],
      timestamp: r[5]
    }));
}

export async function saveMessage(msg) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "MESSAGES!A2:F",
    valueInputOption: "RAW",
    requestBody: {
      values: [[
        msg.chat_id,
        msg.sender_id,
        msg.username,
        msg.picture,
        msg.text,
        msg.timestamp
      ]]
    }
  });
}

/* ===== CRYPTO DEMO LOGGING (NEW TABS ONLY) ===== */

export async function logUserKeys(d) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "USERS_KEYS!A2:D",
    valueInputOption: "RAW",
    requestBody: { values: [[d.google_id, d.username, d.privateKey, d.publicKey]] }
  });
}

export async function logChatSecret(d) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "CHAT_SECRETS!A2:E",
    valueInputOption: "RAW",
    requestBody: { values: [[d.chat_id, d.user_a, d.user_b, d.sharedSecret, d.aesKey]] }
  });
}

export async function logPlaintextMessage(d) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "PLAINTEXT_MESSAGES_LOG!A2:D",
    valueInputOption: "RAW",
    requestBody: { values: [[d.chat_id, d.sender, d.plaintext, Date.now()]] }
  });
}

export async function logEncryptedMessage(d) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "ENCRYPTED_MESSAGES_LOG!A2:F",
    valueInputOption: "RAW",
    requestBody: {
      values: [[d.chat_id, d.sender, d.iv, d.ciphertext, d.authTag, Date.now()]]
    }
  });
}

export async function logNetworkTraffic(d) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "NETWORK_TRAFFIC!A2:C",
    valueInputOption: "RAW",
    requestBody: { values: [[d.direction, "WS", JSON.stringify(d.payload)]] }
  });
}

export async function listUsers() {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SPREADSHEET_ID,
    range: "USERS!A2:D"
  });

  const rows = res.data.values || [];

  return rows.map(r => ({
    google_id: r[0],
    username: r[1],
    picture: r[2],
    email: r[3]
  }));
}
