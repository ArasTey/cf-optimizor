# Arpam CDN Config Optimizer

VLESS CDN Configuration Optimizer — a fully static web app that rewrites VLESS URLs for CDN connectivity, entirely in your browser.

No backend. No API. No build step. No dependencies.

## Features

- Parses any VLESS URL and rewrites only what is needed
- Replaces the **destination address** with your CDN IP (default `188.114.97.6`)
- Applies `cs` (cipher suites), `fm` (FinalMask JSON) and `fp` (fingerprint)
- Never touches `host`, `sni`, `path`, `security`, `alpn`, `type`, or any unknown parameter
- No duplicate parameters — existing `cs` / `fm` / `fp` are replaced, not appended
- Preserves the fragment name exactly, including Persian text and emoji flags
- Batch mode: many configurations at once, one per line
- Drag & drop `.txt` import, `Download TXT` export
- `Copy` per config and `Copy All`
- Change summary per config: Added / Updated / preserved
- Dark theme by default with a light theme toggle, inline SVG icons, no emoji icons
- Settings (CDN IP, fingerprint, cipher suites, FinalMask) persist in `localStorage`; configurations never do

## How It Works

​
Paste VLESS → Validate → Parse → Change address → Apply cs → Apply fm → Apply fp
→ Preserve everything else → Reorder for readability → Encode → Show result → Copy

Parameter output order: `cs, path, security, alpn, encryption, fm, insecure, host, fp, type, allowInsecure, sni`, followed by any unknown parameters in their original order.

All values are encoded with `encodeURIComponent()`; nothing is percent-encoded by hand.

## Supported VLESS URLs

​
vless://UUID@IP:PORT?params#name
vless://UUID@DOMAIN:PORT?params#name
vless://UUID@[IPv6]:PORT?params#name

Configurations with more, fewer, or unknown query parameters are supported. Unknown parameters are always preserved.

## Installation

​
git clone https://github.com/<your-user>/arpam-cdn-config-optimizer.git
cd arpam-cdn-config-optimizer

Then simply open `index.html` in a browser. No `npm install`, no `npm run build`.

## GitHub Pages

1. Push `index.html`, `style.css`, `app.js`, `README.md` to your repository.
2. Open **Settings → Pages**.
3. Source: **Deploy from a branch**, branch `main`, folder `/ (root)`.
4. Your app is live at `https://<your-user>.github.io/<repo>/`.

## Privacy

Everything runs locally in your browser. Your configurations are never uploaded, logged, or transmitted. The app makes no network requests other than loading its own static files and the web font.

## Example

**Input**

​
vless://6698a42e-c8e1-42cf-8779-76f065c59f3f@104.16.0.1:443?path=%2FArpamVpn&security=tls&alpn=http%2F1.1%2Ch2&encryption=none&insecure=0&host=dlqpsxwffbaf.dop44.com&fp=chrome&type=ws&allowInsecure=0&sni=dlqpsxwffbaf.dop44.com#🇩🇪 | 10

**Output**

​
vless://6698a42e-c8e1-42cf-8779-76f065c59f3f@188.114.97.6:443?cs=TLS_AES_256_GCM_SHA384%3A...%3ATLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256&path=%2FArpamVpn&security=tls&alpn=http%2F1.1%2Ch2&encryption=none&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22...%5D%7D&insecure=0&host=dlqpsxwffbaf.dop44.com&fp=unsafe&type=ws&allowInsecure=0&sni=dlqpsxwffbaf.dop44.com#%F0%9F%87%A9%F0%9F%87%AA%20%7C%2010

**Changes**

| Field | Result |
| --- | --- |
| Address | `104.16.0.1 → 188.114.97.6` |
| Fingerprint | `chrome → unsafe` |
| Cipher Suites | Added |
| FinalMask | Added |
| host / sni | Preserved |

## Testing

Open the browser console and use the exposed API:

​
ArpamOptimizer.optimizeMultipleConfigs(text, {
cdnIp: '188.114.97.6',
fp: 'unsafe',
cs: ArpamOptimizer.DEFAULTS.cs,
fm: ArpamOptimizer.DEFAULTS.fm
});

Covered cases: existing `fp`, missing `fp`, existing/missing `fm`, existing `cs`, Persian names, emoji names, multiple configs, unknown parameters, and custom CDN IP with untouched `host` / `sni`.

## License

MIT
