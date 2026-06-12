<p align="center">
  <img src="nn.png" alt="What They See - Privacy & Security Scanner" width="100%">
</p>

# What They See - Privacy & Security Scanner

> A powerful Chrome extension that analyzes what websites track, collect, and detect about you — then gives you actionable recommendations to stay safe online.

![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue) ![Chrome](https://img.shields.io/badge/Chrome-Extension-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

### Core Scanning
- **Real-time Privacy Analysis** — Scans any website for tracking elements, third-party scripts, and data collection methods
- **Security Score** — Get an instant A+ to F grade based on 50+ security and privacy factors
- **Deep Scan Engine** — Performs 70+ individual security checks on every page load

### Threat Detection
- **Tracking Pixel Detection** — Identifies hidden 1x1 pixels, invisible iframes, and beacon scripts
- **Fingerprinting Detection** — Catches canvas, WebGL, audio, font, screen, and navigator fingerprinting attempts
- **Cryptomining Detection** — Detects unauthorized cryptocurrency mining scripts (CoinHive, CryptoLoot, etc.)
- **Keylogging Detection** — Identifies suspicious keystroke monitoring patterns
- **Formjacking & Magecart** — Detects payment form tampering and credit card skimming
- **Data Exfiltration** — Spots patterns of unauthorized data being sent to external servers
- **XSS Risk Patterns** — Identifies cross-site scripting vulnerabilities in page scripts
- **SQL Injection Patterns** — Detects suspicious URL parameters that may indicate injection attempts
- **Open Redirect Detection** — Flags potentially malicious redirect chains

### Privacy Analysis
- **Cookie Audit** — Lists all cookies, flags tracking cookies, and checks security attributes (Secure, SameSite, HttpOnly)
- **Evercookie Detection** — Identifies super-persistent tracking cookies that survive browser resets
- **Browser Storage Analysis** — Inspects localStorage, sessionStorage, and IndexedDB for tracking data
- **Clipboard Monitoring** — Detects websites that listen to copy/paste events
- **Geolocation Tracking** — Flags use of location APIs
- **Camera/Microphone Access** — Detects media device API usage
- **WebRTC Leak Detection** — Checks for potential IP leaks through WebRTC

### Network Monitoring
- **Request Categorization** — Automatically classifies network requests as tracking, advertising, social, analytics, CDN, or essential
- **Third-party Domain Tracking** — Lists all external domains contacted by the page
- **Network Timeline** — Visualizes when each request fires during page load
- **Sensitive Data in URLs** — Flags requests that may leak sensitive information in URL parameters

### Security Headers
- **Content Security Policy (CSP)** — Analyzes CSP policy strength and flags unsafe directives
- **HSTS Check** — Verifies HTTP Strict Transport Security configuration
- **X-Frame-Options** — Checks clickjacking protection
- **X-Content-Type-Options** — Verifies MIME type sniffing protection
- **Permissions Policy** — Reviews feature access restrictions

### Advanced Checks
- **Mixed Content Detection** — Finds HTTP resources loaded on HTTPS pages
- **Subresource Integrity (SRI)** — Checks if external scripts have integrity hashes
- **DOM Vulnerabilities** — Identifies dangerous DOM manipulation patterns
- **Shadow DOM Analysis** — Detects hidden elements that may contain tracking code
- **Web Worker Monitoring** — Flags excessive background workers
- **WebAssembly Detection** — Identifies WASM usage that could be used for mining
- **Service Worker Detection** — Checks for active service workers
- **Autofill Abuse Detection** — Spots potential autofill data harvesting

---

## Installation

### Option 1: Download from GitHub
1. Download or clone this repository
2. Open `install.html` in your browser for a visual step-by-step guide
3. Or follow the manual steps below

### Option 2: Manual Installation
1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (toggle in top-right corner)
4. Click **Load unpacked**
5. Select the extension folder
6. The extension icon will appear in your toolbar

### Option 3: Install Guide Page
Open the `install.html` file included in this repository for an interactive, visual installation walkthrough.

---

## Usage

1. **Click the extension icon** in your Chrome toolbar on any website
2. **Click "Start Security Scan"** to analyze the current page
3. **Browse through tabs** to explore different aspects of the analysis:
   - **Overview** — Quick summary with security score and threat chart
   - **Security** — Connection security, headers, form safety, XSS/DOM risks
   - **SSL** — Certificate and encryption details
   - **Headers** — Security header analysis
   - **Privacy** — Cookies, fingerprinting, storage, analytics tools
   - **Cookies** — Detailed cookie breakdown with tracking flags
   - **Threats** — All detected threats sorted by severity
   - **Network** — Domain connections and request categories
   - **Fingerprint** — Device fingerprinting attempts and vectors
   - **Analysis** — Deep scan results with 50+ security checks
   - **Timeline** — Network request waterfall visualization
   - **Tips** — Personalized recommendations based on scan results

---

## Screenshots

<p align="center">
  <img src="nn.png" alt="Banner" width="100%">
</p>

The extension features a dark, modern UI with color-coded severity badges, interactive charts, and a tabbed results layout.

| SSL/TLS Analysis | Security Tips | Fingerprinting Detection |
|:---:|:---:|:---:|
| ![SSL](SSL.png) | ![Tips](Tips.png) | ![Fingerprinting](Finger.png) |

---

## Permissions

| Permission | Purpose |
|------------|---------|
| `scripting` | Inject scan scripts into web pages |
| `activeTab` | Access the current tab for analysis |
| `storage` | Cache scan results locally |
| `cookies` | Analyze cookie security attributes |
| `webRequest` | Monitor network traffic for trackers |
| `notifications` | Alert when new trackers are detected |

---

## Technical Details

- **Manifest Version:** 3
- **Browser:** Google Chrome (and Chromium-based browsers)
- **Architecture:** Service worker background + content script injection
- **Scan Engine:** Rule-based analysis with 70+ detection patterns
- **Privacy:** All analysis runs locally — no data is sent to external servers

---

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

This extension is a security analysis tool designed for educational and defensive purposes. It helps users understand what data websites collect about them. Always practice responsible browsing and keep your browser updated.
