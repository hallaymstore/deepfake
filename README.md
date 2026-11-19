# HALLAYM SHIELD — Multi-user Telegram Security Bot + Opt-in Monitoring (MVP)

**GitHub:** https://github.com/hallaymstore/deepfake  
**Dashboard:** https://hallaym-shield-deepfake.onrender.com

## New bot workflow (Node.js)

Bot feature code: src/security-bot.js and src/apk-inspect.js

1. Create **your own new bot** in @BotFather. Never reuse a bot token from another active service.
2. Configure its token in Render environment: TELEGRAM_BOT_TOKEN. Add MONGODB_URI, TELEGRAM_API_ID, TELEGRAM_API_HASH and stable SESSION_ENCRYPTION_KEY. Never commit these secrets.
3. Bot /start → /connect generates a 10-minute single-use pairing link.
4. User voluntarily authorizes their *own* Telegram account through the existing secure QR web page. The bot does not ask for, receive or record Telegram login codes or 2FA passwords.
5. Server compares Telegram account ID with the bot user who initiated the link. Only an exact match can bind monitoring to that bot chat.
6. New incoming private messages and links are inspected using explainable heuristic rules. APK files (up to 18 MB) can undergo a restricted ZIP structure scan, SHA-256 hash, manifest-presence, DEX and native-library inventory. High/warning events are sent to the linked user's personal bot chat, without copying message text.
7. Users can /status, /pause, /resume or /unlink. /unlink revokes the server-held Telegram session and deletes that account's related logs.
8. Users can forward suspicious texts, URLs or APK files directly to the bot, or reply /scan to a message in a supported bot-visible chat. Telegram privacy and Guest Mode rules constrain which messages a bot can access.

**What is actually analyzed?** URL patterns, file type metadata, archived APK entries and SHA-256. This is **not** a virus signature engine, sandbox, permission analysis, proof of infection or deepfake AI.

**Important restrictions:**
- Telegram QR linking requires another authorized Telegram device. Phone+code login through a secure Mini App has **not** been implemented yet.
- Existing user monitoring inspects new incoming **private** non-secret chats only; no Secret Chats, full historical scraping, groups or channels.
- Render Free sleeps; not 24/7. For genuine continuous monitoring move the worker to a paid always-on host or VPS and add multi-instance locking.
- A Telegram login session is a full-capability account credential: full transparency, encryption, secure deployment, rate controls, privacy policy, audit and user-initiated revocation are mandatory.
- Never use OTP codes in chat, delete user files without confirmation, or submit private Telegram content to external AI services without valid legal/contractual grounds. See Telegram terms: https://core.telegram.org/api/terms

---

# HALLAYM SHIELD — Telegram & Phishing Security MVP

**Live prototype:** https://hallaym-shield-deepfake.onrender.com  
**Repository:** https://github.com/hallaymstore/deepfake  
**Render workspace:** nodechat · Service: hallaym-shield-deepfake

Independent third-party Telegram safety software; **not affiliated with Telegram**.

## MVP capabilities

- Responsive Uzbek dashboard, public manual text/URL phishing checks.
- Optional Telegram user login with QR confirmation (MTProto, not Bot API).
- Risk indicators in new incoming **private** messages, plus document metadata.
- User-specific event history, pause/resume, logout, full revocation.
- AES-256-GCM encrypted Telegram sessions; MongoDB Atlas persistence; event TTL.
- No storage of full message text or attached files.

**Not yet supported:** Real antivirus scanning, file-content analysis, AI deepfake detection, Chrome extension, secret chats, old conversation history or groups/channels. A low-risk rating is never proof that a message is safe. Messages are not forwarded or replied to.

## Render Environment: required setup

This Render service is created and its code deploys. It remains in **setup mode** until private variables are supplied through the Render dashboard under hallaym-shield-deepfake → Environment.

| Name | Value |
| --- | --- |
| MONGODB_URI | Your **rotated** MongoDB Atlas connection URI (keep secret) |
| MONGODB_DB | hallaym_shield_deepfake |
| TELEGRAM_API_ID | Numeric API ID from my.telegram.org |
| TELEGRAM_API_HASH | API hash from my.telegram.org |
| SESSION_ENCRYPTION_KEY | Stable 64-character hexadecimal secret (already configured in Render) |
| PUBLIC_ORIGIN | https://hallaym-shield-deepfake.onrender.com |
| NODE_ENV | production |
| TRUST_PROXY | true |
| EVENT_RETENTION_DAYS | 7 |

**Important security issue:** Existing historical public environment files in other repositories have exposed MongoDB and bot credentials. Rotate these secrets now, especially before deploying a public user-account security product. Do **not** reuse exposed credentials or store them in GitHub code.

Render Free instances sleep when idle, so Telegram monitoring cannot be guaranteed 24/7. Use a paid always-on service or private worker and complete a security audit before onboarding real users.

## Local development

1. Install Node.js 20+.
2. Run: npm install
3. Copy .env.example to .env, provide credentials privately.
4. Run: npm test
5. Run: npm run check
6. Run: npm start
7. Open http://localhost:3000.

QR linking: Telegram → Settings → Devices → Link Desktop Device. The site never requests Telegram OTP or 2FA password. Some accounts with two-step verification may not be supported yet.

## Routes

- GET /api/health — setup status
- POST /api/check — rule-based text check
- POST /api/connect/start — QR login with explicit consent
- GET /api/connect/status — QR login state
- GET /api/account, /api/events, /api/summary, /api/stream — authenticated monitoring
- POST /api/settings — pause/resume
- POST /api/logout — end web session
- DELETE /api/account — revoke Telegram session and erase stored data

## Privacy

Telegram QR authorization gives the server a **full-capability Telegram client session**. Every user must explicitly understand this scope and consent. This prototype only inspects new private incoming messages while connected. Logs store risk metadata, domains, and pseudonymous sender hashes (default seven-day retention), not message bodies or file bytes. Publish Terms, Privacy Policy, deletion requests, incident handling, user notification and audit controls before a public launch. Review Telegram's API terms and data-use restrictions before applying any external AI models to content.
