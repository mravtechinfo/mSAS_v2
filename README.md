# 🛡️ Mobile Security Auditor

> **Unified mobile security analysis suite** — Static analysis for **Android APKs** and **iOS IPA** files.  
> 100% client-side, nothing leaves your browser.

---

## 📋 Overview

**Mobile Security Auditor** combines two powerful static analysis tools into a single, unified interface:

| Tool | Platform | Rules | Focus |
|------|----------|-------|-------|
| [**APK Auditor**](https://github.com/mravtechinfo/apkauditor) | Android | 150+ | DEX bytecode, AndroidManifest, certificates, crypto, storage, webviews |
| [**IPA Auditor**](https://github.com/mravtechinfo/ipaauditor) | iOS | 80+ | Mach-O binaries, Info.plist, provisioning profiles, ATS, entitlements |

Both tools run **entirely in your browser** using Web Workers — no files are ever uploaded to any server.

---

## ✨ Features

### 📱 APK Auditor
- **DEX bytecode analysis** — Parses Dalvik Executable format, extracts class names, method references, and string resources
- **Manifest inspection** — Decodes and audits `AndroidManifest.xml` for debug flags, backup issues, exposed components
- **Certificate validation** — Extracts and analyzes X.509 signing certificate metadata, hash algorithms, validity periods
- **Security rules engine** — 80+ static analysis rules across crypto, network, storage, webview, intent, and code execution categories
- **OWASP MASVS mapping** — Maps findings to OWASP Mobile Application Security Verification Standard categories
- **Entropy-based secret detection** — Identifies hardcoded API keys, tokens, and credentials using Shannon entropy
- **Tracker SDK detection** — Flags known advertisement and analytics SDKs embedded in the app

### 🍎 IPA Auditor
- **Mach-O binary parser** — Extracts load commands, section info, and flags from iOS binaries
- **Property list analysis** — Parses `Info.plist`, `Entitlements.plist`, and embedded configuration files
- **Provisioning profile parser** — Decodes and validates embedded provisioning profiles
- **App Transport Security (ATS) audit** — Deep analysis of ATS exceptions, domain-specific overrides, and NSAppTransportSecurity configuration
- **Privacy compliance checks** — Detects NSPrivacyTracking, NSPrivacyAccessedAPITypes, and other privacy-related plist entries
- **Entitlements risk assessment** — Identifies over-privileged entitlements and capability misuse

### 🔄 Shared
- **Export formats**: JSON, CSV, PDF, SARIF 2.1
- **Report comparison**: Score + Letter Grade (A+ through F) with severity breakdown
- **Component explorer**: Visual listing of activities, services, receivers, and providers
- **File explorer**: Browse extracted APK/IPA contents in-tree view

---

## 🚀 Quick Start

### Option 1: Open directly (no server needed)
Open `index.html` in your browser, then click into **APK Auditor** or **IPA Auditor**.

### Option 2: Serve locally

```bash
# Using Python
python3 -m http.server 8080
# Then open http://localhost:8080 in your browser

# Using Node.js (if you have npx)
npx serve . -p 8080 --no-clipboard --single --cors
```

---

## 🏗️ Project Structure

```
mobile-security-auditor/
├── index.html                  # Central landing page
├── apk-auditor/                # APK Auditor (cloned from apkauditor)
│   ├── index.html              # APK upload & analysis UI
│   ├── src/
│   │   ├── main.js             # UI controller & rendering
│   │   ├── analyzer.worker.js  # Web Worker for background analysis
│   │   ├── core/
│   │   │   ├── engine.js       # Detection rules engine (80+ ANDROID_RULES)
│   │   │   ├── analyzer.js     # Analysis orchestration
│   │   │   ├── entropy.js      # Secret detection via Shannon entropy
│   │   │   ├── export.js       # JSON / CSV / PDF / SARIF export
│   │   │   └── pdf.js          # PDF report generation
│   │   └── styles.css          # Dark theme UI
│   ├── lib/
│   │   ├── jszip.min.js        # ZIP extraction (APK files)
│   │   └── jspdf.umd.min.js    # PDF generation
│   └── docs/screenshots/
│
├── ipa-auditor/                # IPA Auditor (cloned from ipaauditor)
│   ├── index.html              # IPA upload & analysis UI
│   ├── 404.html                # Custom error page
│   ├── src/
│   │   ├── main.js             # UI controller & rendering
│   │   ├── analyzer.worker.js  # Web Worker for background analysis
│   │   ├── core/
│   │   │   ├── analyzer.js     # Analysis orchestration
│   │   │   ├── ats.js          # App Transport Security parser
│   │   │   ├── entropy.js      # Secret detection
│   │   │   ├── export.js       # Export utilities
│   │   │   ├── macho.js        # Mach-O binary parser
│   │   │   ├── pdf.js          # PDF report generation
│   │   │   ├── plist.js        # Binary plist parser
│   │   │   ├── provisioning.js # Provisioning profile parser
│   │   │   └── rules.js        # iOS detection rules (60+ IOS_RULES)
│   │   └── styles.css          # Pink-accent dark theme UI
│   ├── lib/
│   │   ├── jszip.min.js        # ZIP extraction (IPA files)
│   │   └── jspdf.umd.min.js    # PDF generation
│   └── docs/screenshots/
│
├── package.json                # npm package manifest
└── README.md                   # This file
```

---

## ⚙️ How It Works

### Analysis Flow
1. **Upload** — Drag-and-drop or click to select an APK/IPA file
2. **Extract** — JSZip extracts the archive contents in-browser
3. **Parse** — Platform-specific parsers decode binary formats (DEX, Mach-O, plist, XML)
4. **Scan** — 150+ (Android) / 80+ (iOS) static analysis rules run against extracted strings and metadata
5. **Score** — Findings are weighted by severity and computed into a security score (0–1000) + letter grade
6. **Report** — Results displayed across categorized tabs with export capability

### Privacy
**Zero data leaves your machine.** All processing happens via Web Workers in your browser tab. You can even disconnect from the internet after the page loads — the analysis works entirely offline.

---

## 📄 License

This project is licensed under **Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)**.

You are free to **share** (copy and redistribute) the material in any medium or format, under the following terms:
- **Attribution** — You must give appropriate credit to the original author
- **NonCommercial** — You may not use the material for commercial purposes
- **NoDerivatives** — If you remix, transform, or build upon the material, you may not distribute the modified material

See the [LICENSE](LICENSE) file for full terms.

---

## 🙏 Credits

- **[mravtechinfo](https://github.com/mravtechinfo)** — Maintainer of this unified distribution
- **OWASP** — Mobile Application Security Verification Standard (MASVS) framework

---

## ⚠️ Disclaimer

This tool provides **static analysis only** and may produce **false positives**. It is intended as a **first-pass triage tool** and should not be the sole basis for security decisions. Always verify findings through dynamic analysis and manual review before acting on them. Use only on applications you own or have explicit permission to test.
