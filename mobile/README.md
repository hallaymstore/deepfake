# HALLAYM SHIELD Messenger (Android MVP)

Local-first third-party Telegram client prototype built using TDLib. It is **not a Telegram bot**, official Telegram app, or general-purpose antivirus. Only the user may authorize their own account on their Android device.

## Scope
- Telegram login on device (phone/confirmation code/2FA and email when supported by TDLib).
- Telegram chat list, messages, text send and suspicious message/document-name warnings.
- User-selected APK file inspection: SHA-256, ZIP structure and requested permissions, accessibility service flag.
- No background polling every 10 seconds, no silent file deletion, no arbitrary app storage access.
- No remote message-content upload to Render. Dashboard remains separate.

## Android build
- Android SDK 35, Java 17+, Gradle 8.9 or newer, AGP 8.7.3.
- Set TELEGRAM_API_ID and TELEGRAM_API_HASH in the **build environment** (not in git).
- Compile from mobile/ using gradle assembleDebug.
- Requires internet to download io.github.tdlib-android:core:0.1.1. This prebuilt TDLib dependency includes JNI ABIs.
- The Android debug APK is for testing; do not distribute to real users before a full security review, test of authorization flows and Telegram terms compliance.

## Limitations
AI deepfake/video analysis, Gmail integration, third-party Instagram notification monitoring, Chrome website notification control, silent quarantine and system-wide protection are not part of this version. APK permission detections are *indicators*, not proof of malware. Official Telegram/Play Protect cannot be replaced by this app.

Source: https://github.com/hallaymstore/deepfake
