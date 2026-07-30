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
