# HALLAYM SHIELD

Opt-in Telegram personal-message threat monitoring (MVP). A separate Telegram account is connected by QR approval; this is **not** a Telegram Bot API bot.

## Deployment

Node.js 20+, MongoDB Atlas, teleproto MTProto; `npm install && npm start`.

Required environment variables: `MONGODB_URI`, `MONGODB_DB=hallaym_shield_deepfake`, `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `SESSION_ENCRYPTION_KEY` (64 hex characters), `PUBLIC_ORIGIN` (exact HTTPS origin for production), `NODE_ENV=production`, `TRUST_PROXY=true`.

This MVP screens new incoming private message text/URL and file metadata using deterministic rules. It does **not** claim full antivirus, Chrome notification blocking or deepfake detection. Media downloads are disabled. Raw messages and credentials are not stored in risk logs.

Never commit `.env`, Telegram sessions, MongoDB connection strings or keys. Published historical credentials from other repositories need rotation.
