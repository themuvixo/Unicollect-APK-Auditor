# Changelog

## 1.0.0 · Scan Bay (Initial Release)

Created by muvixo.

### ✨ New
- Completely new visual design ("Scan Bay"): graphite / light-table themes, signal-orange brand colour, false-colour X-ray byte wall, new cards, tabs, badges, charts and overlays.
- Animated dark / light theme switch: circular reveal from the toggle (View Transitions API) with a colour cross-fade fallback, plus a sun / moon cross-scale icon.
- Real site preloader that tracks the actual stylesheet, fonts and scripts, with real byte counts from the Resource Timing API.
- "Created by muvixo" watermark in the UI, footer and all exports (PDF, HTML, Markdown, JSON, SARIF, summary).

### 🎞️ Motion
- All entrances and exits use fade, scale or colour only. Removed every slide (x / y) animation, including the old scan beam and cursor spotlight.
- Proper exit animations for command palette, settings drawer, shortcuts, export menu, scan overlay, toasts and expanded findings.
- Tab switches and landing / report switches cross-fade with View Transitions.
- Toggle switches cross-scale their knob instead of sliding it.

### 🐛 Fixed
- The landing "bytes" stat was a hard-coded 0. It now shows real bytes scanned locally (persisted in this browser), while uploads stay at 0 B.
- The scan overlay now shows live bytes read from disk while the file is loading.


## 4.0.0 · Unicollect APK Auditor

### ✨ New
- Rebrand to **Unicollect APK Auditor** with a new SVG logo and app icons.
- Complete UI redesign: black / white / blue system, self-hosted fonts, byte-scanner drop zone, sticky tabs.
- **Insights** tab: hardening checklist, MASVS category bars, OWASP Mobile Top 10 heatmap, hot files, file fingerprints.
- **Baseline diff** against a previous JSON export, plus automatic diff for re-scans of the same package.
- **Scan history** on the start page (metadata only, can be disabled).
- **Sample report** (`?sample=1`).
- **Command palette** (`Ctrl/⌘ + K`), shortcut sheet (`?`), `N` new scan, `T` theme.
- **Settings drawer**: theme, density, findings per page, mask secrets, auto-expand issues, history, reduce motion.
- **HTML** and **Markdown** report exports, **Copy summary**, **Copy manifest XML**.
- Installable `manifest.webmanifest`, print styles.

### 🐛 Fixed
- Trackers rendered as empty tags (engine returns names, UI expected objects).
- App header showed "Unknown" when the APK has no manifest; now falls back to the file name.

### 🧹 Removed
- PNG screenshots in `docs/` (replaced by SVG artwork).
- External Google Fonts requests and the `CNAME` file.
