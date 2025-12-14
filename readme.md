# HybridSecure Chat — Minimal Demo (Google Forms + Sheets)

This repo is a minimal encrypted chat demo (per-recipient X25519 → HKDF → AES-GCM) that uses:
- Google Form for writes (POST to `formResponse`),
- Google Sheet (responses) published as CSV for reads,
- Static frontend hosted on GitHub Pages.

## Files
- `index.html` — main single-page app (UI).
- `css/styles.css` — minimal styling.
- `js/utils.js` — helpers (base64, CSV parse).
- `js/crypto.js` — libsodium + WebCrypto glue.
- `js/app.js` — main app: UI, crypto, write/read logic.

## Setup
1. Create Google Form with fields (short answer):
   - roomId, username, msgType, senderPub, recipient, ciphertext, iv, salt, hkdfInfo, timestamp
2. Get the pre-filled link to discover `entry.xxxxx` names (map them to fields).
3. Compute Form action URL: `https://docs.google.com/forms/d/e/<FORM_ID>/formResponse`
4. Link the form to a Google Sheet (Responses → Create spreadsheet).
5. Publish the responses sheet to web as CSV:
   - In the Sheet: File → Publish to web → select the responses sheet → format CSV → Publish → copy CSV URL.
6. Edit `js/app.js`:
   - Replace `FORM_ACTION_URL`, each `ENTRY_*` constant, and `SHEET_CSV_URL`.
7. Run locally (optional): `python -m http.server 5500` and open `http://localhost:5500`.
8. Deploy to GitHub Pages (push repo → Settings → Pages → main branch → root).

## Demo instructions
- Open the app on laptop and the published Google Sheet in another browser tab.
- Claim a unique username and click "Generate Keys".
- On another device or incognito, open the app, claim another username and generate keys.
- Send messages — ciphertext rows will appear in the Google Sheet. Show the Sheet tab to the judges to demonstrate traffic.

## Notes
- This is a demo. Google Sheets published CSV is public; do not send real secrets.
- Form POSTs use `mode: "no-cors"`; check the Google Sheet to confirm writes.
=======
# HybridSecure Chat — Minimal Demo (Google Forms + Sheets)

This repo is a minimal encrypted chat demo (per-recipient X25519 → HKDF → AES-GCM) that uses:
- Google Form for writes (POST to `formResponse`),
- Google Sheet (responses) published as CSV for reads,
- Static frontend hosted on GitHub Pages.

## Files
- `index.html` — main single-page app (UI).
- `css/styles.css` — minimal styling.
- `js/utils.js` — helpers (base64, CSV parse).
- `js/crypto.js` — libsodium + WebCrypto glue.
- `js/app.js` — main app: UI, crypto, write/read logic.

## Setup
1. Create Google Form with fields (short answer):
   - roomId, username, msgType, senderPub, recipient, ciphertext, iv, salt, hkdfInfo, timestamp
2. Get the pre-filled link to discover `entry.xxxxx` names (map them to fields).
3. Compute Form action URL: `https://docs.google.com/forms/d/e/<FORM_ID>/formResponse`
4. Link the form to a Google Sheet (Responses → Create spreadsheet).
5. Publish the responses sheet to web as CSV:
   - In the Sheet: File → Publish to web → select the responses sheet → format CSV → Publish → copy CSV URL.
6. Edit `js/app.js`:
   - Replace `FORM_ACTION_URL`, each `ENTRY_*` constant, and `SHEET_CSV_URL`.
7. Run locally (optional): `python -m http.server 5500` and open `http://localhost:5500`.
8. Deploy to GitHub Pages (push repo → Settings → Pages → main branch → root).

## Demo instructions
- Open the app on laptop and the published Google Sheet in another browser tab.
- Claim a unique username and click "Generate Keys".
- On another device or incognito, open the app, claim another username and generate keys.
- Send messages — ciphertext rows will appear in the Google Sheet. Show the Sheet tab to the judges to demonstrate traffic.

## Notes
- This is a demo. Google Sheets published CSV is public; do not send real secrets.
- Form POSTs use `mode: "no-cors"`; check the Google Sheet to confirm writes.
>>>>>>> f62f278 (first push)
