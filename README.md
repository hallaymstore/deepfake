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
