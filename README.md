<div align="center">

# Aras | CDN Config Optimizer

**VLESS & Trojan CDN Configuration Optimizer â€” 100% client-side.**

Paste VLESS/Trojan URLs or subscription links, get optimized configs for CDN fronting in one click.  
No backend. No build step. Nothing ever leaves your browser.

[Live Demo](https://arastey.github.io/cf-optimizor/) | [Report an issue](https://github.com/ArasTey/cf-optimizor/issues) | [Telegram](https://t.me/imArasTey)

</div>

---

## Contents

- [Overview](#overview)
- [Features](#features)
- [Supported Apps](#supported-apps)
- [How It Works](#how-it-works)
- [Aras Mode](#aras-mode)
- [Default Values](#default-values)
- [Supported Inputs](#supported-inputs)
- [Usage](#usage)
- [JavaScript API](#javascript-api)
- [Privacy](#privacy)
- [Installation](#installation)
- [Copyright](#copyright)

## Features

- **One-click optimization** â€” automatically sets the CDN address, `fp`, `cs` (Cipher Suites) and `fm` (FinalMask).
- **VLESS + Trojan support** â€” both protocols are fully optimized. Other protocols are passed through untouched.
- **Subscription support** â€” paste a subscription URL (`http(s)://...`) and the tool fetches and extracts configs. If the sub is filtered on your network, it automatically retries through multiple CORS proxies.
- **ZEUS format support** â€” handles JSON subscription responses and base64-encoded subscription content.
- **Never rebuilds blindly** â€” each URL is parsed first, then only the required parameters are added or replaced. Everything else is preserved exactly.
- **Fragment / name safe** â€” Persian text, emoji and spaces in the `#name` part survive untouched.
- **Multiple configs at once** â€” one per line (or bulk from subscription), each optimized in the same output.
- **Change summary** â€” see exactly what changed.
- **Advanced settings** â€” custom CDN IP, fingerprint (`unsafe` / `chrome` / `firefox` / `safari` / `edge` / `random`), custom Cipher Suites and custom FinalMask JSON with live validation.
- **Aras Mode** â€” one-click lighter profile for Instagram and similar services.
- **JSON output** â€” export optimized configs as a valid JSON array for desktop/iOS clients.
- **Drag & drop `.txt` import** and **Download TXT** export.
- **Dark + light theme**, remembered across visits, with no flash on load.
- **Fully responsive** â€” mobile-first, comfortable on desktop.
- **Private by design** â€” only UI settings are stored in `localStorage`. Your config URLs and subscription data are never saved, logged or uploaded.

---

## Supported Apps

| Platform | Apps |
| --- | --- |
| **Android** | [PattNG](https://github.com/patterniha/v2rayNG/releases/latest) | [v2rayNG](https://github.com/2dust/v2rayNG/releases/latest) | [V2rayTun](https://play.google.com/store/apps/details?id=com.v2raytun.android) |
| **iOS** | [Streisand](https://apps.apple.com/app/streisand/id6450534064) | INCY | Happ |
| **Windows** | [v2rayN v7.24.7](https://github.com/2dust/v2rayN/releases/tag/7.24.7) |

**Important notes:**

- **Android** â€“ use normal or Aras output directly in the apps.
- **iOS** â€“ first try normal output. If it doesn't work, use the **JSON output**.
- **Windows** â€“ only JSON output works with v2rayN v7.24.7. Ping may show `-1` and port may show `0`, but the connection can still work.

> These optimized configurations use parameters (`fm`, `cs`, `fp=unsafe`) that only the recommended clients support correctly.

---

## How It Works

1. **Parse** â€” VLESS/Trojan URLs and subscription responses are parsed into their components: UUID/password, host, port, query parameters and fragment. Nothing is guessed or regenerated.
2. **Validate** â€” scheme must be `vless://` or `trojan://`. UUID (for VLESS) must match the standard v4 format, and the host must exist.
3. **Replace** â€” only the address, `fp`, `cs` and `fm` are changed during optimization.
4. **Preserve** â€” `path`, `security`, `alpn`, `encryption`, `host`, `type`, `sni`, `insecure`, `allowInsecure`, the port, UUID/password and unknown parameters are kept as-is. `host=` and `sni=` are never modified.
5. **Rebuild** â€” parameters are re-emitted in a fixed order, duplicates removed, every key and value passed through `encodeURIComponent()`, then the original `#fragment` is re-appended.

### Parameter output order

```text
cs, path, security, alpn, encryption, fm, insecure, host, fp, type, allowInsecure, sni
```

Unknown parameters are appended after these, in their original order.

---

## Aras Mode

Aras Mode is a special lightweight profile designed for Instagram and similar services where speed is more important than maximum fragmentation.

When you press the **Aras Mode** button, the tool re-optimizes the same input configs using:

- **Fragment** â€“ `1-1` only
- **Cipher Suites** â€“ `TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`
- **Fingerprint** â€“ `chrome`

### Usage

1. Optimize your configs normally.
2. Click **Aras Mode**.
3. Wait for the output to update.
4. Copy or download the Aras configs.

To get **JSON output from Aras Mode**, enable Aras Mode first, then click **JSON Output**.

---

## Example

**Input (VLESS)**

```text
vless://11111111-2222-3333-4444-555555555555@104.16.0.1:443?type=ws&security=tls&path=%2Fpath&host=example.com&sni=example.com&encryption=none&fp=chrome#ðŸ‡©ðŸ‡ª Ø¢Ù„Ù…Ø§Ù† - Ø³Ø±ÙˆØ± Û±
```

**Output (normal)**

```text
vless://11111111-2222-3333-4444-555555555555@188.114.97.6:443?cs=TLS_AES_256_GCM_SHA384%3ATLS_CHACHA20_POLY1305_SHA256%3A...&path=%2Fpath&security=tls&encryption=none&fm=%7B%22tcp%22%3A%5B%7B%22fragment%22%3A%22tlshello%22...%7D%5D%7D&host=example.com&fp=unsafe&type=ws&sni=example.com#ðŸ‡©ðŸ‡ª Ø¢Ù„Ù…Ø§Ù† - Ø³Ø±ÙˆØ± Û±
```

Only the intended optimization parameters change. The hostname/SNI, path, type, port, credentials and fragment name remain preserved.

---

## Default Values

### CDN IP

```text
188.114.97.6
```

### Fingerprint â€” Normal

```text
unsafe
```

### Fingerprint â€” Aras

```text
chrome
```

### Cipher Suites â€” Normal

```text
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
```

### Cipher Suites â€” Aras

```text
TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
```

### FinalMask â€” Normal

```json
{
  "tcp": [
    {
      "type": "fragment",
      "settings": {
        "packets": "tlshello",
        "lengths": ["5", "94", "1"],
        "delays": ["0"],
        "maxSplit": "0"
      }
    },
    {
      "type": "fragment",
      "settings": {
        "packets": "1-1",
        "lengths": ["109", "1"],
        "delays": ["1"],
        "maxSplit": "355"
      }
    }
  ]
}
```

### FinalMask â€” Aras

```json
{
  "tcp": [
    {
      "type": "fragment",
      "settings": {
        "packets": "tlshello",
        "lengths": ["1-1"],
        "delays": ["0"],
        "maxSplit": "0"
      }
    }
  ]
}
```

---

## Supported Inputs

| Type | Supported |
| --- | --- |
| `vless://` direct URL | âœ… |
| `trojan://` direct URL | âœ… |
| `vmess://`, `ss://`, `hysteria2://`, `tuic://` | âœ… passed through unchanged |
| Subscription link (`http(s)://...`) | âœ… |
| ZEUS subscription format | âœ… |
| Base64-encoded subscription content | âœ… |
| Multiple configs | âœ… |
| IPv4, IPv6 (`[::1]:443`) and domain hosts | âœ… |
| WebSocket, gRPC, TCP, XHTTP, HTTPUpgrade | âœ… |
| TLS, Reality, none | âœ… |
| Persian / emoji / spaces in fragments | âœ… |
| Existing `fp`, `cs`, `fm` values | âœ… replaced |
| Unknown / custom parameters | âœ… preserved |
| Duplicate parameters | âœ… deduplicated |
| Missing port | âœ… preserved as-is |

---

## File Structure

```text
cf-optimizor/
â”œâ”€â”€ index.html
â”œâ”€â”€ README.md
â””â”€â”€ assets/
```

No frameworks, no bundler, no npm. Every icon is an inline SVG; the favicon is a data URI.

---

## Installation

### Locally

```bash
git clone https://github.com/ArasTey/cf-optimizor.git
cd cf-optimizor
```

Open `index.html` directly, or serve it with:

```bash
python3 -m http.server 8080
```

Then open:

```text
http://localhost:8080
```

### GitHub Pages

1. Push the repository to GitHub.
2. Open **Settings â†’ Pages**.
3. Select the main branch and `/ (root)`.
4. Save.

---

## Usage

1. Paste one or more VLESS/Trojan URLs or a subscription link into the textarea.
2. Optionally open **Advanced Settings**.
3. Press **Optimize** or `Ctrl / Cmd + Enter`.
4. Review the output.
5. Use **Copy All**, **Download TXT**, or **JSON Output**.
6. For Aras Mode, click **Aras Mode** after optimization.
7. Import the result into your supported client.

---

## JavaScript API

All core functions are exposed on `window.ArasOptimizer`:

```javascript
ArasOptimizer.parseVless(url)
ArasOptimizer.parseTrojan(url)
ArasOptimizer.validateConfig(url)
ArasOptimizer.normalizeParams(params)
ArasOptimizer.sortParams(params)
ArasOptimizer.getParam(params, key)
ArasOptimizer.setParam(params, key, value)
ArasOptimizer.encodeFinalMask(json)
ArasOptimizer.optimizeVless(url, opts)
ArasOptimizer.optimizeTrojan(url, opts)
ArasOptimizer.buildVless(config)
ArasOptimizer.buildTrojan(config)
ArasOptimizer.optimizeMultipleConfigs(text, opts)
ArasOptimizer.fetchSubscription(url)
ArasOptimizer.copyToClipboard(text)
ArasOptimizer.downloadConfigs(list, filename)
ArasOptimizer.DEFAULTS
ArasOptimizer.ARAS_DEFAULTS
```

Quick check:

```javascript
ArasOptimizer.optimizeVless(
  'vless://11111111-2222-3333-4444-555555555555@104.16.0.1:443?type=ws&security=tls&fp=chrome#Test'
).url
```

---

## Privacy

- Everything runs in your browser.
- There is no application backend, API, analytics or telemetry.
- Config URLs and subscription data are not saved to `localStorage`.
- Only UI preferences are stored locally under:
  - `aras_optimizer_settings`
  - `aras_theme`
- Clearing browser data removes those settings.

> **Important:** subscription fetching necessarily makes a network request to the subscription URL and, when enabled by the application, its configured proxy endpoints. This does not mean the application stores your subscription data on its own server.

---

## Credits

Developed by **Aras** with â˜•

- Telegram â€” [@imArasTey](https://t.me/imArasTey)
- Free configurations â€” ZEUS PANEL
- Android client â€” v2rayNG
- Windows client â€” v2rayN

---

# Copyright & Usage Restrictions

Copyright Â© 2026 **Aras**. All rights reserved.

This repository and its contents are proprietary unless a separate written license from **Aras** explicitly states otherwise.

Without prior written permission from Aras, you may **not**:

- Copy or republish this project or substantial portions of it.
- Fork, mirror, clone or redistribute the repository.
- Rebrand the project and publish it as another project.
- Remove, hide or modify copyright, attribution or ownership notices.
- Sell, sublicense or commercially redistribute the project.
- Publish modified or derivative versions.
- Reuse the source code, UI, design, documentation or branding in another public project.
- Claim the project or any derivative work as your own.

### GitHub Forks

A public GitHub repository may technically expose GitHub's native **Fork** functionality. GitHub platform functionality cannot be disabled by a README or source-code license.

Accordingly, the repository owner does **not** grant permission to create or distribute a fork. Any GitHub fork or derivative copy is subject to these usage restrictions unless Aras has granted written permission.

### No Warranty

The software is provided for its intended purpose without warranty of any kind. Aras is not responsible for damages, configuration failures, connectivity issues, service interruptions or misuse resulting from the software.

For permission requests, contact **@imArasTey**.

---

---

## Copyright & Usage Restrictions

Copyright Â© 2026 **Aras**. All rights reserved.

This project is proprietary and is **not released under an open-source license**.

Without explicit written permission from Aras, you may not:

- Copy or republish this project or substantial portions of it.
- Create, distribute or publish forks or mirrors.
- Rebrand the project and publish it as another project.
- Remove or modify copyright, attribution or ownership notices.
- Publish modified or derivative versions.
- Sell, sublicense or commercially redistribute the source.
- Reuse substantial portions of the source code, UI, design or documentation.
- Claim the project or a derivative work as your own.

### GitHub Forks

GitHub may technically display a **Fork** option depending on repository visibility and account settings.

A GitHub interface option does **not** constitute permission from Aras.

Unauthorized forks, mirrors, copies and derivative publications are not permitted.

### Permission Requests

For written permission or licensing inquiries, contact:

**Telegram:** [@imArasTey](https://t.me/imArasTey)

---

<div align="center">

**Built by Aras**

Simple. Fast. Client-side.

</div>
