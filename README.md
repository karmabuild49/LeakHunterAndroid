# LeakHunter v2.0 Android starter project

Anonymous-inspired defensive security dashboard for Android. This is an Android Studio project source archive, **not a prebuilt APK**.

## Features in this starter build
- Neon green / black mobile dashboard and terminal-style log.
- Public certificate-transparency hostname discovery via crt.sh.
- DNS resolution for discovered hosts.
- Basic HTTPS response and selected security-header checks.
- JSON report export from the current scan.
- No server-side storage or account system.

## Build an APK
1. Install Android Studio on a computer from https://developer.android.com/studio
2. Extract this ZIP.
3. In Android Studio choose **Open** and select the `LeakHunterAndroid` folder.
4. Allow Gradle sync and install any requested Android SDK (compile SDK 35).
5. Choose **Build > Build Bundle(s) / APK(s) > Build APK(s)**.
6. The debug APK is usually at `app/build/outputs/apk/debug/app-debug.apk`.
7. Transfer that APK to your Android phone and open it. You may need to allow installation from that file manager.

## Important
- This project has not been compiled or tested on a physical Android device in this environment.
- Network calls require internet access. Some domains may reject HEAD requests or time out.
- The scan is a basic exposure review, not a penetration test or guarantee of security.
- Only scan domains you own or have explicit authorization to assess.
- This starter UI does not yet integrate the Python script's HIBP email check, password check, or local metadata importer. Those should be added separately with careful key handling and privacy controls.
- No private doxxing collection or stolen-password retrieval is included.
