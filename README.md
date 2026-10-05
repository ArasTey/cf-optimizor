<div align="center">

# Aras | CDN Config Optimizer

**VLESS & Trojan CDN Configuration Optimizer with ECH support — 100% client-side.**

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
- [Tabs](#tabs)
- [Optimizer Tab](#optimizer-tab)
- [ECH Tab](#ech-tab)
- [Default Values](#default-values)
- [Supported Inputs](#supported-inputs)
- [File Structure](#file-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Privacy](#privacy)
- [Credits](#credits)
- [Copyright & Usage Restrictions](#copyright--usage-restrictions)

## Overview

The project has **two independent tabs**:

| Tab | Purpose |
| --- | --- |
| **بهینه‌ساز** (Optimizer) | Optimize VLESS/Trojan configs for CDN fronting |
| **تبدیل به ECH** (ECH Converter) | Generate ECH-enabled variants of VLESS/Trojan configs |

Each tab has its own input area, its own advanced settings panel, and its own output area. Switching tabs does not lose your input or settings.

---

## Features

### Optimizer tab

- **One-click optimization** — sets `cs` (Cipher Suites), `fm` (FinalMask) and optionally the address and `fp` on each config.
- **VLESS + Trojan support** — both protocols are fully optimized. Other protocols are passed through untouched.
- **Subscription support** — paste a subscription URL (`http(s)://...`) and the tool fetches and extracts configs. If the sub is filtered, it automatically retries through multiple CORS proxies.
- **ZEUS format support** — handles JSON subscription responses and base64-encoded subscription content.
- **Never rebuilds blindly** — each URL is parsed first, then only the required parameters are added or replaced.
- **Fragment / name safe** — Persian text, emoji and spaces in the `#name` part survive untouched.
- **Multiple configs at once** — one per line, or bulk from subscription.
- **Advanced settings** — optional server address, fingerprint (`unsafe` / `chrome` / `firefox` / `safari` / `edge` / `random`), custom Cipher Suites, and custom FinalMask JSON with live validation.
- **JSON output** — export optimized configs as a valid JSON array for desktop/iOS clients.
- **Network-aware stream settings** — generates the correct `ws` / `grpc` / `xhttp` / `tcp` / `http` / `quic` block based on each config's `type`.
- **Security-aware TLS block** — emits `tlsSettings`, `xtlsSettings`, `realitySettings` or no TLS block based on `security`.
- **Parameter fidelity** — reads and preserves `alpn`, `insecure` / `allowInsecure`, `mux` and other per-config parameters.

### ECH tab

- **ECH conversion for vless and trojan** — build ECH-enabled variants of your configs in one click.
- **Full ECH list input** — paste one complete ECH value per line (e.g. `cloudflare-ech.com+udp://1.1.1.1`). Each line produces a separate variant of every input config.
- **Custom name template** — configure the remark suffix using `{name}`, `{ip}`, `{domain}` and `{type}` placeholders.
- **Original remark preserved** — the original `#fragment` of each config is kept as the base name, and the template is applied on top.
- **ECH-aware JSON output** — produces a valid JSON array where `echConfigList` is set on the TLS block of every ECH variant.
- **Live regeneration** — changing the ECH list or name template updates the output immediately.

### Shared

- **Drag & drop `.txt` import** and **Download TXT** export.
- **Dark + light theme**, remembered across visits, with no flash on load.
- **Fully responsive** — mobile-first, comfortable on desktop.
- **Persistent settings** — optimizer and ECH preferences are stored in `localStorage`.
- **Private by design** — only UI settings are stored in `localStorage`. Your config URLs and subscription data are never saved, logged or uploaded.

---

## Supported Apps

| Platform | Apps |
| --- | --- |
| **Android** | [PattNG](https://github.com/patterniha/PattNG/releases/latest), [v2rayNG](https://github.com/2dust/v2rayNG/releases/latest), [V2rayTun](https://play.google.com/store/apps/details?id=com.v2raytun.android) |
| **iOS** | [Streisand](https://apps.apple.com/app/streisand/id6450534064), INCY, Happ |
| **Windows** | [PattN](https://github.com/patterniha/PattN/releases/latest), v2rayN |

**Important notes:**

- **Android** — use normal or ECH output directly in the apps.
- **iOS** — first try normal output. If it doesn't work, use the **JSON output**.
- **Windows** — PattN supports both normal and JSON. v2rayN may require JSON.
- **ECH support** — not all clients support `echConfigList`. Recommended: PattNG (Android), PattN (Windows), recent Streisand (iOS).

> These optimized configurations use parameters (`fm`, `cs`, `ech`) that only the recommended clients support correctly.

---

## How It Works

### Optimizer

1. **Parse** — VLESS/Trojan URLs and subscription responses are parsed into their components: UUID/password, host, port, query parameters and fragment. Nothing is guessed or regenerated.
2. **Validate** — scheme must be `vless://` or `trojan://`. UUID (for VLESS) must match the standard v4 format, and the host must exist.
3. **Replace** — only `cs` and `fm` are always replaced; `fp` and address are replaced only if you set them in Advanced Settings.
4. **Preserve** — `path`, `security`, `alpn`, `encryption`, `host`, `type`, `sni`, `insecure`, `allowInsecure`, the port, UUID/password and unknown parameters are kept as-is.
5. **Rebuild** — parameters are re-emitted in a fixed order, duplicates removed, every key and value passed through `encodeURIComponent()`, then the original `#fragment` is re-appended.

### ECH Converter

1. **Parse inputs** — same rules as the optimizer.
2. **Strip any previous `ech=`** — the config is cleaned so a fresh value can be applied.
3. **For each ECH line** in the ECH list, and for each parsed config, a new variant is created with `ech=<value>` appended.
4. **Remark** is rebuilt using the name template.
5. **Output** — an ordered list of ECH variants plus a JSON array where each entry has `echConfigList` set on the TLS block.

### Parameter output order

Optimizer tab:

```text
cs, path, security, alpn, encryption, fm, insecure, host, fp, type, allowInsecure, sni
```

ECH tab:

```text
path, security, alpn, encryption, insecure, host, fp, ech, type, allowInsecure, sni, cs, fm
```

Unknown parameters are appended after these, in their original order.

---

## Tabs

The UI is split into two tabs at the top of the page. Each tab has:

- Its own input area (configs or subscription link).
- Its own advanced settings accordion.
- Its own output area with Copy All, Download TXT and JSON Output buttons.

Switching tabs preserves your input and settings in both tabs.

---

## Optimizer Tab

### Inputs

- Config list — one `vless://` or `trojan://` URL per line, a subscription link, or a base64-encoded subscription body.
- Advanced Settings (optional):
  - Server address — if set, overrides the host of every config.
  - Fingerprint — unsafe / chrome / firefox / safari / edge / random. Default: not modified.
  - Cipher Suites (`cs`) — applied to every config.
  - FinalMask (`fm`) — JSON fragment profile, applied to every config.

### Output

The optimized configs in URL form. Pressing خروجی JSON switches the output to a JSON array where each config becomes a full client profile with DNS, inbounds, outbounds, routing, etc.

---

## ECH Tab

### Inputs

- Config list — one `vless://` or `trojan://` URL per line.
- ECH list — one complete ECH value per line. Example:

```text
cloudflare-ech.com+udp://1.1.1.1
cloudflare-ech.com+udp://8.8.8.8
```

- Name template — controls the remark of each generated config.

### Supported placeholders

| Placeholder | Description |
| --- | --- |
| `{name}` | Original config remark. If present in the template, it replaces the default name + template behavior. |
| `{ip}` | The IP extracted from the ECH line (after `udp://`). |
| `{domain}` | The domain extracted from the ECH line (before `+`). |
| `{type}` | Protocol (`vless` or `trojan`). |

### Output

For every combination of (input config) × (ECH line), one config is generated.

Example: 2 configs × 2 ECH lines = 4 output configs.

Each output config has:

- `ech=<value>` set in its URL query.
- A remark built from the name template.
- `echConfigList: "<value>"` set on the TLS block of the corresponding JSON entry.

---

## Example

### Input (VLESS)

```text
vless://11111111-2222-3333-4444-555555555555@104.16.0.1:443?type=ws&security=tls&path=%2Fpath&host=example.com&sni=example.com&encryption=none&fp=chrome#🇩🇪 آلمان - سرور ۱
```

### Optimizer output

```text
vless://11111111-2222-3333-4444-555555555555@104.16.0.1:443?cs=TLS_AES_256_GCM_SHA384%3A...&path=%2Fpath&security=tls&encryption=none&fm=%7B%22tcp%22%3A...%7D&host=example.com&fp=chrome&type=ws&sni=example.com#🇩🇪 آلمان - سرور ۱
```

### ECH output (ECH line `cloudflare-ech.com+udp://1.1.1.1`, template `ECH {ip}`)

```text
vless://11111111-2222-3333-4444-555555555555@104.16.0.1:443?path=%2Fpath&security=tls&encryption=none&host=example.com&fp=chrome&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&type=ws&sni=example.com#🇩🇪 آلمان - سرور ۱ ECH 1.1.1.1
```

Only the intended parameters change. Hostname, SNI, path, type, port, credentials and original fragment name remain preserved.

---

## Default Values

### Server address

```text
(empty — the address of each config is not modified)
```

### Fingerprint

```text
(empty — the fingerprint of each config is not modified; JSON output defaults to unsafe)
```

### Cipher Suites

```text
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
```

### FinalMask

```json
{
  "tcp": [
    {
      "type": "fragment",
      "settings": {
        "packets": "tlshello",
        "lengths": ["0", "104", "1"],
        "delays": ["0"],
        "maxSplit": "0"
      }
    },
    {
      "type": "fragment",
      "settings": {
        "packets": "1-1",
        "lengths": ["114", "1"],
        "delays": ["1"],
        "maxSplit": "11"
      }
    }
  ]
}
```

### ECH list

```text
cloudflare-ech.com+udp://1.1.1.1
cloudflare-ech.com+udp://8.8.8.8
```

### Name template

```text
ECH {ip}
```

---

## Supported Inputs

| Type | Supported |
| --- | --- |
| `vless://` direct URL | ✅ |
| `trojan://` direct URL | ✅ |
| `vmess://`, `ss://`, `hysteria2://`, `tuic://` | ✅ passed through unchanged |
| Subscription link (`http(s)://...`) | ✅ |
| ZEUS subscription format | ✅ |
| Base64-encoded subscription content | ✅ |
| Multiple configs | ✅ |
| IPv4, IPv6 (`[::1]:443`) and domain hosts | ✅ |
| WebSocket, gRPC, TCP, XHTTP, HTTPUpgrade | ✅ |
| TLS, Reality, XTLS, none | ✅ |
| Custom ALPN lists | ✅ |
| `insecure` / `allowInsecure` | ✅ |
| `mux` and `muxConcurrency` | ✅ |
| Persian / emoji / spaces in fragments | ✅ |
| Existing `fp`, `cs`, `fm`, `ech` values | ✅ replaced |
| Unknown / custom parameters | ✅ preserved |
| Duplicate parameters | ✅ deduplicated |
| Missing port | ✅ preserved as-is |
| Configs with `$` in the remark | ✅ |

---

## File Structure

```text
cf-optimizor/
└── index.html
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
2. Open Settings → Pages.
3. Select the main branch and `/` (root).
4. Save.

---

## Usage

### Optimizer tab

1. Paste one or more VLESS/Trojan URLs or a subscription link into the textarea.
2. Optionally open Advanced Settings.
3. Press بهینه‌سازی or Ctrl / Cmd + Enter.
4. Review the output.
5. Use کپی همه, دانلود TXT, or خروجی JSON.

### ECH tab

1. Switch to the تبدیل به ECH tab.
2. Paste your VLESS/Trojan configs into the input area.
3. Open تنظیمات پیشرفته ECH.
4. Set the ECH list (one full value per line) and the name template.
5. Press ساخت ECH + JSON or Ctrl / Cmd + Enter.
6. Use کپی همه, دانلود TXT, or خروجی JSON.

---

## Privacy

- Everything runs in your browser.
- There is no application backend, API, analytics or telemetry.
- Config URLs and subscription data are not saved to localStorage.
- Only UI preferences are stored locally under:
  - `vpn_opt_prefs_v1` — optimizer settings
  - `vpn_ech_prefs_v1` — ECH settings
  - `vpn_theme` — theme preference
- Clearing browser data removes those settings.

Important: subscription fetching necessarily makes a network request to the subscription URL and, when enabled, its configured proxy endpoints. This does not mean the application stores your subscription data on its own server.

---

## Credits

Developed by Aras with ☕

- Telegram — @imArasTey
- Free configurations — ZEUS PANEL
- Android client — PattNG / v2rayNG
- Windows client — PattN / v2rayN

---

## Copyright & Usage Restrictions

Copyright © 2026 Aras. All rights reserved.

This repository and its contents are proprietary unless a separate written license from Aras explicitly states otherwise.

Without prior written permission from Aras, you may not:

- Copy or republish this project or substantial portions of it.
- Fork, mirror, clone or redistribute the repository.
- Rebrand the project and publish it as another project.
- Remove, hide or modify copyright, attribution or ownership notices.
- Sell, sublicense or commercially redistribute the project.
- Publish modified or derivative versions.
- Reuse the source code, UI, design, documentation or branding in another public project.
- Claim the project or any derivative work as your own.

### GitHub Forks

A public GitHub repository may technically expose GitHub's native Fork functionality. GitHub platform functionality cannot be disabled by a README or source-code license.

Accordingly, the repository owner does not grant permission to create or distribute a fork. Any GitHub fork or derivative copy is subject to these usage restrictions unless Aras has granted written permission.

### No Warranty

The software is provided for its intended purpose without warranty of any kind. Aras is not responsible for damages, configuration failures, connectivity issues, service interruptions or misuse resulting from the software.

For permission requests, contact @imArasTey.

---

<div align="center">

Built by Aras

Simple. Fast. Client-side.

</div>
