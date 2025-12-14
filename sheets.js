import { google } from "googleapis";
import dotenv from "dotenv";

dotenv.config();

/* ================= ENV VALIDATION ================= */

const {
  SERVICE_ACCOUNT_EMAIL,
  SERVICE_ACCOUNT_PRIVATE_KEY,
  SPREADSHEET_ID
} = process.env;

if (!SERVICE_ACCOUNT_EMAIL) {
  throw new Error("Missing SERVICE_ACCOUNT_EMAIL");
}

if (!SERVICE_ACCOUNT_PRIVATE_KEY) {
  throw new Error("Missing SERVICE_ACCOUNT_PRIVATE_KEY");
}

if (!SPREADSHEET_ID) {
  throw new Error("Missing SPREADSHEET_ID");
}

/* ================= AUTH ================= */

const privateKey = SERVICE_ACCOUNT_PRIVATE_KEY.includes("\\n")
  ? SERVICE_ACCOUNT_PRIVATE_KEY.replace(/\\n/g, "\n") // local .env
  : SERVICE_ACCOUNT_PRIVATE_KEY;                      // Railway

const auth = new google.auth.JWT(
  SERVICE_ACCOUNT_EMAIL,
  null,
  privateKey,
  ["https://www.googleapis.com/auth/spreadsheets"]
);

const sheets = google.sheets({ version: "v4", auth });

/* ================= USERS ================= */
/*
USERS sheet layout:
A: google_id
B: username
C: picture
D: email
*/

export async function createUser({ google_id, username, picture, email }) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "USERS!A:D",
    valueInputOption: "RAW",
    requestBody: {
      values: [[google_id, username, picture, email]]
    }
  });
}

export async function getUserByGoogleId(google_id) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SPREADSHEET_ID,
    range: "USERS!A2:D"
  });

  const rows = res.data.values || [];
  const row = rows.find(r => r[0] === google_id);

  if (!row) return null;

  return {
    google_id: row[0],
    username: row[1],
    picture: row[2],
    email: row[3]
  };
}

export async function listUsers() {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SPREADSHEET_ID,
    range: "USERS!A2:D"
  });

  return (res.data.values || []).map(r => ({
    google_id: r[0],
    username: r[1],
    picture: r[2],
    email: r[3]
  }));
}

/* ================= MESSAGES ================= */
/*
MESSAGES sheet layout:
A: chat_id
B: sender_id
C: username
D: message
E: timestamp
*/

export async function saveMessage(msg) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "MESSAGES!A:E",
    valueInputOption: "RAW",
    requestBody: {
      values: [[
        msg.chat_id,
        msg.sender_id,
        msg.username,
        msg.text,
        msg.timestamp
      ]]
    }
  });
}

export async function getMessages(chat_id) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SPREADSHEET_ID,
    range: "MESSAGES!A2:E"
  });

  return (res.data.values || [])
    .filter(r => r[0] === chat_id)
    .map(r => ({
      chat_id: r[0],
      sender_id: r[1],
      username: r[2],
      text: r[3],
      timestamp: r[4]
    }));
}

/* ================= CRYPTO / LOGGING ================= */
/*
These sheets are for judge visibility
*/

export async function logUserKeys({ google_id, username, privateKey, publicKey }) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "USER_KEYS!A:D",
    valueInputOption: "RAW",
    requestBody: {
      values: [[google_id, username, privateKey, publicKey]]
    }
  });
}

export async function logChatSecret({ chat_id, user_a, user_b, sharedSecret, aesKey }) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "CHAT_KEYS!A:E",
    valueInputOption: "RAW",
    requestBody: {
      values: [[chat_id, user_a, user_b, sharedSecret, aesKey]]
    }
  });
}

export async function logPlaintextMessage({ chat_id, sender, plaintext }) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "PLAINTEXT!A:C",
    valueInputOption: "RAW",
    requestBody: {
      values: [[chat_id, sender, plaintext]]
    }
  });
}

export async function logEncryptedMessage({ chat_id, sender, iv, ciphertext, authTag }) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "ENCRYPTED!A:E",
    valueInputOption: "RAW",
    requestBody: {
      values: [[chat_id, sender, iv, ciphertext, authTag]]
    }
  });
}

export async function logNetworkTraffic({ direction, payload }) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: SPREADSHEET_ID,
    range: "TRAFFIC!A:B",
    valueInputOption: "RAW",
    requestBody: {
      values: [[direction, JSON.stringify(payload)]]
    }
  });
}
