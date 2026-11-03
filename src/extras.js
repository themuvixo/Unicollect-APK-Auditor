/* Unicollect APK Auditor · v1.0.0 features · Created by muvixo
   Insights tab, baseline diff, scan history, sample report, command palette,
   settings drawer, shortcuts, extra exports, byte-wall scanner animation. */
(function () {
'use strict';

const UCA = window.UCA || {};
const $  = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const esc = (t) => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const toast = (m, t) => (UCA.toast ? UCA.toast(m, t) : console.log(m));
const Report = () => (window.IPAA && window.IPAA.Report) || null;

/* ---------------- settings ---------------- */
const DEFAULTS = { density: 'comfortable', perPage: 50, maskSecrets: false, autoExpand: false, history: true, reduceMotion: false };
const KEY_SETTINGS = 'uca.settings';
const KEY_HISTORY = 'uca.history';
let settings = Object.assign({}, DEFAULTS, readJSON(KEY_SETTINGS, {}));

function readJSON(k, fb) { try { const v = JSON.parse(localStorage.getItem(k) || 'null'); return v == null ? fb : v; } catch (_) { return fb; } }
function writeJSON(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) {} }
function saveSettings() { writeJSON(KEY_SETTINGS, settings); }

function applySettings() {
    const html = document.documentElement;
    html.classList.toggle('density-compact', settings.density === 'compact');
    html.classList.toggle('mask-secrets', !!settings.maskSecrets);
    html.classList.toggle('reduce-motion', !!settings.reduceMotion);
    if (UCA.State) {
        const n = parseInt(settings.perPage, 10) || 50;
        if (UCA.State.findingsPerPage !== n) {
            UCA.State.findingsPerPage = n;
            UCA.State.findingsPage = 0;
            UCA.renderFindings && UCA.renderFindings();
        }
    }
    syncSettingsUI();
}

function syncSettingsUI() {
    $$('.seg[data-setting]').forEach(seg => {
        const key = seg.dataset.setting;
        const val = key === 'theme' ? (document.documentElement.dataset.theme || 'dark') : String(settings[key]);
        $$('button', seg).forEach(b => b.classList.toggle('active', b.dataset.value === val));
    });
    $$('input.switch[data-setting]').forEach(i => { i.checked = !!settings[i.dataset.setting]; });
}

function setupSettings() {
    $$('.seg[data-setting]').forEach(seg => seg.addEventListener('click', (e) => {
        const b = e.target.closest('button[data-value]');
        if (!b) return;
        const key = seg.dataset.setting;
        if (key === 'theme') { UCA.setTheme && UCA.setTheme(b.dataset.value, b); syncSettingsUI(); return; }
        settings[key] = key === 'perPage' ? parseInt(b.dataset.value, 10) : b.dataset.value;
        saveSettings(); applySettings();
    }));
    $$('input.switch[data-setting]').forEach(i => i.addEventListener('change', () => {
        settings[i.dataset.setting] = i.checked;
        saveSettings(); applySettings();
        if (i.dataset.setting === 'history' && !i.checked) toast('History off. Existing entries stay until you clear them.');
        if (i.dataset.setting === 'autoExpand' && i.checked) expandIssues();
    }));
    const reset = $('#resetSettingsBtn');
    reset && reset.addEventListener('click', () => {
        settings = Object.assign({}, DEFAULTS);
        try { localStorage.removeItem(KEY_SETTINGS); localStorage.removeItem(KEY_HISTORY); localStorage.removeItem(KEY_BYTES); } catch (_) {}
        applySettings(); renderHistory(); renderBytesCounter();
        toast('Settings and history reset', 'success');
    });
    document.addEventListener('uca:theme', syncSettingsUI);
}

/* ---------------- overlays ---------------- */
let lastFocus = null;
function openOverlay(id) {
    closeOverlays();
    const o = document.getElementById(id);
    if (!o) return;
    lastFocus = document.activeElement;
    if (UCA.animShow) UCA.animShow(o); else o.hidden = false;
    const f = $('input, button', o);
    setTimeout(() => f && f.focus(), 10);
}
function closeOverlays() {
    let closed = false;
    $$('.overlay').forEach(o => {
        if (!o.hidden && !o.classList.contains('is-leaving')) {
            closed = true;
            if (UCA.animHide) UCA.animHide(o); else o.hidden = true;
        }
    });
    if (closed && lastFocus && lastFocus.focus) lastFocus.focus();
    return closed;
}
function setupOverlays() {
    $$('.overlay').forEach(o => {
        o.addEventListener('mousedown', (e) => { if (e.target === o) closeOverlays(); });
        $$('[data-close]', o).forEach(b => b.addEventListener('click', closeOverlays));
    });
    $('#settingsBtn') && $('#settingsBtn').addEventListener('click', () => { syncSettingsUI(); openOverlay('settingsOverlay'); });
    $('#shortcutsBtn') && $('#shortcutsBtn').addEventListener('click', () => openOverlay('shortcutsOverlay'));
    $('#paletteBtn') && $('#paletteBtn').addEventListener('click', openPalette);
}

/* ---------------- command palette ---------------- */
let paletteIdx = 0;
let paletteItems = [];
function inApp() { const a = $('#appContainer'); return !!(a && a.classList.contains('active')); }
function hasResults() { return !!(UCA.State && UCA.State.currentResults); }

function commands() {
    const list = [];
    const tabs = [['overview', 'Overview', '▦'], ['insights', 'Insights', '▮'], ['findings', 'Findings', '⛨'], ['manifest', 'Manifest', '≡'], ['components', 'Components', '⬡'], ['cert', 'Certificate', '⚿'], ['explorer', 'Explorer', '▤']];
    if (hasResults()) {
        tabs.forEach(([id, name, ic], i) => list.push({ group: 'Go to', icon: ic, name: name, hint: 'Alt+' + (i + 1), run: () => { if (!inApp() && UCA.showApp) UCA.showApp(() => UCA.switchTab(id)); else UCA.switchTab(id); } }));
        list.push({ group: 'Export', icon: '⤓', name: 'Export PDF report', run: () => clickExport('pdf') });
        list.push({ group: 'Export', icon: '⤓', name: 'Export HTML report', run: () => runX('html') });
        list.push({ group: 'Export', icon: '⤓', name: 'Export Markdown', run: () => runX('md') });
        list.push({ group: 'Export', icon: '⤓', name: 'Export JSON', run: () => clickExport('json') });
        list.push({ group: 'Export', icon: '⤓', name: 'Export CSV', run: () => clickExport('csv') });
        list.push({ group: 'Export', icon: '⤓', name: 'Export SARIF 2.1', run: () => clickExport('sarif') });
        list.push({ group: 'Export', icon: '⧉', name: 'Copy summary to clipboard', run: copySummary });
        list.push({ group: 'Analysis', icon: '⇄', name: 'Load baseline JSON for diff', run: () => { UCA.switchTab('insights'); $('#baselineInput').click(); } });
        list.push({ group: 'Analysis', icon: '◎', name: 'Show issues only', run: () => { UCA.switchTab('findings'); const b = $('.filter-btn[data-filter="issue"]'); b && b.click(); } });
        list.push({ group: 'Analysis', icon: '▾', name: 'Expand all findings', run: () => { UCA.switchTab('findings'); $('#expandAllBtn').click(); } });
    }
    list.push({ group: 'App', icon: '＋', name: 'New scan', hint: 'N', run: () => UCA.openFilePicker && UCA.openFilePicker() });
    list.push({ group: 'App', icon: '◐', name: 'Open sample report', run: openSample });
    list.push({ group: 'App', icon: '⌂', name: 'Back to start page', run: () => UCA.showLanding && UCA.showLanding() });
    list.push({ group: 'App', icon: '◑', name: 'Toggle theme', hint: 'T', run: toggleTheme });
    list.push({ group: 'App', icon: '⚙', name: 'Settings', run: () => { syncSettingsUI(); openOverlay('settingsOverlay'); } });
    list.push({ group: 'App', icon: '⌨', name: 'Keyboard shortcuts', hint: '?', run: () => openOverlay('shortcutsOverlay') });
    list.push({ group: 'App', icon: '◫', name: settings.maskSecrets ? 'Unmask secrets' : 'Mask secrets (screen share)', run: () => { settings.maskSecrets = !settings.maskSecrets; saveSettings(); applySettings(); } });
    list.push({ group: 'App', icon: '⇵', name: settings.density === 'compact' ? 'Comfortable density' : 'Compact density', run: () => { settings.density = settings.density === 'compact' ? 'comfortable' : 'compact'; saveSettings(); applySettings(); } });
    list.push({ group: 'App', icon: '⌫', name: 'Clear scan history', run: clearHistory });
    return list;
}
function openPalette() {
    openOverlay('paletteOverlay');
    const input = $('#paletteInput');
    input.value = '';
    paletteIdx = 0;
    renderPalette('');
}
function renderPalette(q) {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    paletteItems = commands().filter(c => { const hay = (c.group + ' ' + c.name).toLowerCase(); return words.every(w => hay.includes(w)); });
    if (paletteIdx >= paletteItems.length) paletteIdx = Math.max(0, paletteItems.length - 1);
    const el = $('#paletteList');
    if (!paletteItems.length) { el.innerHTML = '<div class="palette-empty">Nothing matches “' + esc(q) + '”</div>'; return; }
    let out = '', g = '';
    paletteItems.forEach((c, i) => {
        if (c.group !== g) { g = c.group; out += '<div class="palette-group">' + esc(g) + '</div>'; }
        out += '<button type="button" class="palette-item' + (i === paletteIdx ? ' active' : '') + '" data-i="' + i + '" role="option" aria-selected="' + (i === paletteIdx) + '">' +
            '<span class="pi-icon" aria-hidden="true">' + esc(c.icon) + '</span><span>' + esc(c.name) + '</span>' + (c.hint ? '<span class="pi-hint">' + esc(c.hint) + '</span>' : '') + '</button>';
    });
    el.innerHTML = out;
    const act = $('.palette-item.active', el);
    act && act.scrollIntoView({ block: 'nearest' });
}
function runPalette(i) {
    const c = paletteItems[i];
    if (!c) return;
    closeOverlays();
    setTimeout(() => { try { c.run(); } catch (e) { toast(e.message, 'error'); } }, 0);
}
function setupPalette() {
    const input = $('#paletteInput');
    if (!input) return;
    input.addEventListener('input', () => { paletteIdx = 0; renderPalette(input.value); });
    input.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown') { e.preventDefault(); paletteIdx = Math.min(paletteItems.length - 1, paletteIdx + 1); renderPalette(input.value); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); paletteIdx = Math.max(0, paletteIdx - 1); renderPalette(input.value); }
        else if (e.key === 'Enter') { e.preventDefault(); runPalette(paletteIdx); }
    });
    $('#paletteList').addEventListener('click', (e) => { const b = e.target.closest('.palette-item'); if (b) runPalette(parseInt(b.dataset.i, 10)); });
    $('#paletteList').addEventListener('mousemove', (e) => {
        const b = e.target.closest('.palette-item');
        if (!b) return;
        const i = parseInt(b.dataset.i, 10);
        if (i !== paletteIdx) { paletteIdx = i; $$('.palette-item').forEach(x => x.classList.toggle('active', x === b)); }
    });
}

/* ---------------- keyboard ---------------- */
function toggleTheme() {
    const cur = document.documentElement.dataset.theme || 'dark';
    UCA.setTheme && UCA.setTheme(cur === 'dark' ? 'light' : 'dark', $('#themeToggle'));
}
function setupKeys() {
    document.addEventListener('keydown', (e) => {
        const ae = document.activeElement;
        const inField = ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT' || ae.isContentEditable);
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
            e.preventDefault();
            const po = $('#paletteOverlay');
            const open = !po.hidden && !po.classList.contains('is-leaving');
            if (open) closeOverlays(); else openPalette();
            return;
        }
        if (e.key === 'Escape') { if (closeOverlays()) { e.stopImmediatePropagation(); } return; }
        if (inField || e.ctrlKey || e.metaKey || e.altKey) return;
        if (!$$('.overlay').every(o => o.hidden || o.classList.contains('is-leaving'))) return;
        if (e.key === '?') { e.preventDefault(); openOverlay('shortcutsOverlay'); }
        else if (e.key === 'n' || e.key === 'N') { if (!document.body.classList.contains('analyzing')) UCA.openFilePicker && UCA.openFilePicker(); }
        else if (e.key === 't' || e.key === 'T') { toggleTheme(); }
    }, true);
}

/* ---------------- exports ---------------- */
function clickExport(kind) {
    const b = $('.export-item[data-export="' + kind + '"]');
    b && b.click();
}
function runX(kind) {
    const r = UCA.State && UCA.State.currentResults;
    if (!r || !Report()) return;
    try { Report().exportReport(kind, r); toast('Exported ' + (kind === 'md' ? 'Markdown' : 'HTML') + ' report', 'success'); }
    catch (e) { toast('Export failed: ' + e.message, 'error'); }
}
async function copyText(text, okMsg) {
    try { await navigator.clipboard.writeText(text); toast(okMsg || 'Copied', 'success'); }
    catch (_) {
        const ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); toast(okMsg || 'Copied', 'success'); } catch (e) { toast('Copy failed', 'error'); }
        ta.remove();
    }
}
function copySummary() {
    const r = UCA.State && UCA.State.currentResults;
    if (!r || !Report()) return;
    copyText(Report().summaryText(r), 'Summary copied');
}
function setupExports() {
    $$('.export-item[data-xexport]').forEach(b => b.addEventListener('click', () => {
        runX(b.dataset.xexport);
        const dd = $('#exportDropdown'); if (dd) dd.hidden = true;
        const btn = $('#exportMenuBtn'); if (btn) btn.setAttribute('aria-expanded', 'false');
    }));
    $('#copySummaryBtn') && $('#copySummaryBtn').addEventListener('click', copySummary);
    $('#copyManifestBtn') && $('#copyManifestBtn').addEventListener('click', () => {
        const r = UCA.State && UCA.State.currentResults;
        if (r && r.manifestStr) copyText(r.manifestStr, 'Manifest XML copied'); else toast('No manifest to copy', 'error');
    });
}

/* ---------------- insights ---------------- */
const MASVS_LABELS = { STORAGE: 'storage', CRYPTO: 'crypto', AUTH: 'auth', NETWORK: 'network', PLATFORM: 'platform', CODE: 'code quality', RESILIENCE: 'resilience', PRIVACY: 'privacy' };
function categoryOf(f) {
    const m = String(f.masvs || '').toUpperCase().match(/^[A-Z]+/);
    if (m && MASVS_LABELS[m[0]]) return MASVS_LABELS[m[0]];
    if (f.category && f.category !== 'other') return f.category;
    return 'other';
}
function issues(r) { return (r.groupedFindings && r.groupedFindings.issue) || []; }

function renderChecklist(r) {
    const el = $('#insightsChecklist');
    if (!el || !Report()) return;
    const h = Report().hardening(r);
    const pct = h.total ? Math.round(100 * h.passed / h.total) : 0;
    $('#checklistScore').textContent = h.passed + ' / ' + h.total + ' passed';
    el.innerHTML = '<div class="checklist-meter"><span class="checklist-meter-val">' + pct + '%</span><div class="checklist-meter-bar"><i style="width:' + pct + '%"></i></div></div>' +
        '<div class="checklist">' + h.items.map(i => {
            const cls = i.pass === null ? 'na' : i.pass ? 'pass' : 'fail';
            const mark = i.pass === null ? '–' : i.pass ? '✓' : '✕';
            return '<div class="check-item ' + cls + '"><span class="check-mark" aria-hidden="true">' + mark + '</span><div><div class="check-name">' + esc(i.name) +
                '<span class="sr-only">: ' + (i.pass === null ? 'not applicable' : i.pass ? 'pass' : 'fail') + '</span></div><div class="check-desc">' + esc(i.desc) + '</div></div></div>';
        }).join('') + '</div>';
}
function renderCategories(r) {
    const el = $('#insightsCategories');
    if (!el) return;
    const counts = {};
    issues(r).forEach(f => { const c = categoryOf(f); counts[c] = (counts[c] || 0) + Math.max(1, (f.instances || []).length); });
    const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    if (!rows.length) { el.innerHTML = '<div class="no-data">No issues. Nice.</div>'; return; }
    const max = rows[0][1];
    el.innerHTML = '<div class="bars">' + rows.map(([k, v], i) =>
        '<div class="bar-row"><span class="bar-row-label">' + esc(k) + '</span><div class="bar-track"><div class="bar-fill" style="width:' + Math.max(4, Math.round(100 * v / max)) + '%;animation-delay:' + (i * 60) + 'ms"></div></div><span class="bar-val">' + v + '</span></div>').join('') +
        '</div><p class="landing-note" style="margin:14px 0 0">Instances per MASVS area, issues only.</p>';
}
function renderOwasp(r) {
    const el = $('#insightsOwasp');
    if (!el) return;
    const counts = {};
    issues(r).forEach(f => { const m = String(f.owasp || '').toUpperCase().match(/M(10|[1-9])/); if (m) counts['M' + m[1]] = (counts['M' + m[1]] || 0) + 1; });
    let html = '<div class="owasp-grid">';
    for (let i = 1; i <= 10; i++) {
        const n = counts['M' + i] || 0;
        const lvl = n === 0 ? '' : n === 1 ? 'l1' : n <= 2 ? 'l2' : 'l3';
        html += '<div class="owasp-cell ' + lvl + '" title="OWASP Mobile M' + i + ': ' + n + ' rule(s)"><b>M' + i + '</b><span>' + (n ? n + ' rule' + (n === 1 ? '' : 's') : 'clear') + '</span></div>';
    }
    el.innerHTML = html + '</div><p class="landing-note" style="margin:14px 0 0">Rules hit per OWASP Mobile Top 10 tag. Darker means more.</p>';
}
function renderHotFiles(r) {
    const el = $('#insightsFiles');
    if (!el) return;
    const byFile = new Map();
    issues(r).forEach(f => (f.instances || []).forEach(i => { if (i.file) byFile.set(i.file, (byFile.get(i.file) || 0) + 1); }));
    const top = [...byFile.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (!top.length) { el.innerHTML = '<div class="no-data">No files with issues</div>'; return; }
    el.innerHTML = '<div class="hot-files">' + top.map(([f, n]) =>
        '<button type="button" class="hot-file" data-file="' + esc(f) + '" title="' + esc(f) + '"><span class="hot-file-name">&lrm;' + esc(f) + '&lrm;</span><span class="hot-file-count">' + n + '</span></button>').join('') + '</div>';
    $$('.hot-file', el).forEach(b => b.addEventListener('click', () => {
        const f = b.dataset.file;
        if (/\.java$/.test(f)) {
            UCA.switchTab('findings');
            const s = $('#findingsSearchInput');
            if (s) { s.value = f.replace(/\.java$/, '').split('.').pop(); s.dispatchEvent(new Event('input')); }
        } else if (UCA.navigateToFile) UCA.navigateToFile(f, 0);
    }));
}
async function renderHashes(r, file) {
    const el = $('#insightsHashes');
    if (!el) return;
    const ai = r.appInfo || {};
    const rows = [];
    if (ai.md5) rows.push(['MD5', ai.md5]);
    if (ai.sha256) rows.push(['SHA-256', ai.sha256]);
    const cert = r.certInfo;
    if (cert && cert.fingerprintSHA256) rows.push(['CERT', cert.fingerprintSHA256]);
    const draw = (extra) => {
        const all = rows.concat(extra || []);
        el.innerHTML = all.length ? '<div class="hash-list">' + all.map(([k, v]) =>
            '<div class="hash-row"><b>' + esc(k) + '</b><code>' + esc(v) + '</code><button type="button" class="copy-btn" data-copy="' + esc(v) + '" aria-label="Copy ' + esc(k) + '">⧉</button></div>').join('') + '</div>'
            : '<div class="no-data">No fingerprints</div>';
        $$('[data-copy]', el).forEach(b => b.addEventListener('click', () => copyText(b.dataset.copy, 'Hash copied')));
    };
    draw([['SHA-1', '…'], ['SHA-512', '…']].filter(() => !!file));
    if (file && window.crypto && crypto.subtle && file.size < 400 * 1024 * 1024) {
        try {
            const buf = await file.arrayBuffer();
            const hex = (ab) => Array.from(new Uint8Array(ab)).map(b => b.toString(16).padStart(2, '0')).join('');
            const [s1, s512] = await Promise.all([crypto.subtle.digest('SHA-1', buf), crypto.subtle.digest('SHA-512', buf)]);
            draw([['SHA-1', hex(s1)], ['SHA-512', hex(s512)]]);
        } catch (_) { draw(); }
    } else draw();
}

/* ---------------- baseline diff ---------------- */
let baseline = null;
function ruleSetFromResults(r) {
    const m = new Map();
    issues(r).forEach(f => m.set(f.ruleId || f.ruleName, f.ruleName || f.ruleId));
    return m;
}
function ruleSetFromExport(j) {
    const m = new Map();
    (j.findings || []).forEach(f => { if ((f.severity || 'issue') === 'issue') m.set(f.ruleId || f.ruleName, f.ruleName || f.ruleId); });
    if (!m.size && j.groupedFindings) (j.groupedFindings.issue || []).forEach(f => m.set(f.ruleId || f.ruleName, f.ruleName || f.ruleId));
    return m;
}
function renderDiff(r) {
    const el = $('#insightsDiff');
    if (!el) return;
    if (!baseline) {
        const prev = previousScanOf(r);
        if (prev && prev.issueRules) {
            baseline = { label: 'previous scan of v' + (prev.version || '?') + ' (' + new Date(prev.at).toLocaleDateString() + ')', score: prev.score, rules: new Map(prev.issueRules.map(x => [x[0], x[1]])), auto: true };
        }
    }
    if (!baseline) {
        el.innerHTML = '<div class="diff-intro"><span>Export JSON from an older build, then load it here to see what got fixed and what is new. Scans of the same package are compared automatically when history is on.</span></div>';
        return;
    }
    const cur = ruleSetFromResults(r);
    const added = [...cur.entries()].filter(([k]) => !baseline.rules.has(k));
    const fixed = [...baseline.rules.entries()].filter(([k]) => !cur.has(k));
    const kept = [...cur.entries()].filter(([k]) => baseline.rules.has(k));
    const delta = (r.securityScore != null && baseline.score != null) ? (r.securityScore - baseline.score) : null;
    const col = (cls, title, list) => '<div class="diff-col ' + cls + '"><h4>' + title + ' · ' + list.length + '</h4>' +
        (list.length ? list.slice(0, 40).map(([, n]) => '<div class="diff-item">' + esc(n) + '</div>').join('') : '<div class="diff-empty">None</div>') + '</div>';
    el.innerHTML = '<p class="landing-note" style="margin:0 0 14px">Compared with ' + esc(baseline.label) + '.</p>' +
        '<div class="diff-summary">' +
        '<div class="diff-stat new"><b>' + added.length + '</b><span>new issues</span></div>' +
        '<div class="diff-stat fixed"><b>' + fixed.length + '</b><span>resolved</span></div>' +
        '<div class="diff-stat"><b>' + (delta == null ? '–' : (delta > 0 ? '+' : '') + delta) + '</b><span>score change</span></div></div>' +
        '<div class="diff-cols">' + col('new', 'New', added) + col('fixed', 'Resolved', fixed) + col('kept', 'Still open', kept) + '</div>';
}
function setupBaseline() {
    const input = $('#baselineInput');
    $('#baselineBtn') && $('#baselineBtn').addEventListener('click', () => input && input.click());
    input && input.addEventListener('change', async () => {
        const f = input.files[0];
        input.value = '';
        if (!f) return;
        try {
            const j = JSON.parse(await f.text());
            const rules = ruleSetFromExport(j);
            const app = j.app || j.appInfo || {};
            baseline = { label: f.name + (app.versionName ? ' (v' + app.versionName + ')' : ''), score: j.securityScore, rules };
            const r = UCA.State && UCA.State.currentResults;
            if (r) renderDiff(r);
            UCA.switchTab && UCA.switchTab('insights');
            toast('Baseline loaded · ' + rules.size + ' issue rules', 'success');
        } catch (e) { toast('Not a valid JSON report: ' + e.message, 'error'); }
    });
}

/* ---------------- history ---------------- */
function history() { return readJSON(KEY_HISTORY, []); }
function previousScanOf(r) {
    const ai = r.appInfo || {};
    if (!ai.packageName) return null;
    return history().find(h => h.pkg === ai.packageName && h.sha256 !== ai.sha256) || null;
}
function recordHistory(r) {
    if (!settings.history || r.__sample) return;
    const ai = r.appInfo || {};
    const s = r.summary || {};
    const entry = {
        name: ai.appLabel || ai.packageName || ai.fileName || 'APK', pkg: ai.packageName || '', version: ai.versionName || '',
        fileName: ai.fileName || '', size: ai.fileSize || '', sha256: ai.sha256 || '', score: r.securityScore,
        issue: s.issue || 0, info: s.info || 0, secure: s.secure || 0, at: Date.now(),
        issueRules: issues(r).slice(0, 200).map(f => [f.ruleId || f.ruleName, f.ruleName || f.ruleId]),
    };
    const list = history().filter(h => !(entry.sha256 && h.sha256 === entry.sha256));
    list.unshift(entry);
    writeJSON(KEY_HISTORY, list.slice(0, 12));
    renderHistory();
}
function scoreClass(s) { return s >= 80 ? 'good' : s >= 60 ? 'ok' : s >= 40 ? 'meh' : 'bad'; }
function timeAgo(t) {
    const d = (Date.now() - t) / 1000;
    if (d < 60) return 'just now';
    if (d < 3600) return Math.floor(d / 60) + ' min ago';
    if (d < 86400) return Math.floor(d / 3600) + ' h ago';
    return new Date(t).toLocaleDateString();
}
function renderHistory() {
    const sec = $('#historySection'), el = $('#historyList');
    if (!sec || !el) return;
    const list = history();
    sec.hidden = list.length === 0;
    el.innerHTML = list.map((h, i) =>
        '<article class="history-card"><button type="button" class="history-del" data-del="' + i + '" aria-label="Remove ' + esc(h.name) + ' from history">✕</button>' +
        '<div class="history-top"><span class="history-score ' + scoreClass(h.score || 0) + '">' + (h.score != null ? h.score : '–') + '</span>' +
        '<div style="min-width:0"><div class="history-name">' + esc(h.name) + '</div><div class="history-pkg mono">' + esc(h.pkg || h.fileName) + (h.version ? ' · v' + esc(h.version) : '') + '</div></div></div>' +
        '<div class="history-meta"><span class="iss"><b>' + h.issue + '</b> issues</span><span><b>' + h.info + '</b> info</span><span><b>' + h.secure + '</b> secure</span><span style="margin-left:auto">' + esc(timeAgo(h.at)) + '</span></div></article>').join('');
    $$('[data-del]', el).forEach(b => b.addEventListener('click', () => {
        const l = history(); l.splice(parseInt(b.dataset.del, 10), 1); writeJSON(KEY_HISTORY, l); renderHistory();
    }));
}
function clearHistory() {
    try { localStorage.removeItem(KEY_HISTORY); } catch (_) {}
    renderHistory();
    toast('Scan history cleared', 'success');
}

/* ---------------- auto-expand ---------------- */
function expandIssues() {
    if (!settings.autoExpand) return;
    $$('#findingsList .finding-card[data-severity="issue"]').forEach(card => {
        const h = $('.finding-header', card), b = $('.finding-body', card);
        if (h && b && h.getAttribute('aria-expanded') !== 'true') { h.setAttribute('aria-expanded', 'true'); b.hidden = false; }
    });
}

/* ---------------- sample ---------------- */
function openSample() {
    if (!window.UCA_SAMPLE) { toast('Sample report missing', 'error'); return; }
    baseline = null;
    UCA.loadResults(JSON.parse(JSON.stringify(window.UCA_SAMPLE)), { sample: true });
    toast('Sample report loaded · synthetic data');
}

/* ---------------- byte wall (landing signature) ----------------
   False-colour X-ray: each byte cell colours in and out in a diagonal
   wave (pure colour animation, nothing moves). Bytes re-roll quietly. */
function setupByteWall() {
    const wall = $('#byteWall');
    if (!wall) return;
    const COLS = 12, ROWS = 15;
    const hex = () => (Math.random() * 256 | 0).toString(16).padStart(2, '0').toUpperCase();
    const header = ['50', '4B', '03', '04', '14', '00', '08', '08', '08', '00', 'A1', '5C'];
    const tones = ['', 't-m', 't-g'];
    let out = '';
    for (let i = 0; i < COLS * ROWS; i++) {
        const r = Math.floor(i / COLS), c = i % COLS;
        if (i < COLS) { out += '<span class="head">' + header[i] + '</span>'; continue; }
        const band = Math.floor(r / 5);
        const tone = Math.random() < 0.62 ? tones[band % 3] : tones[(Math.random() * 3) | 0];
        const delay = ((c + r) * 0.11 + Math.random() * 0.25).toFixed(2);
        out += '<span class="' + tone + '" style="--d:' + delay + 's">' + hex() + '</span>';
    }
    wall.innerHTML = out;
    const cells = $$('span:not(.head)', wall);
    const still = () => settings.reduceMotion || matchMedia('(prefers-reduced-motion: reduce)').matches;
    setInterval(() => {
        if (still() || document.hidden || document.body.classList.contains('in-app')) return;
        for (let k = 0; k < 9; k++) { const c = cells[(Math.random() * cells.length) | 0]; c.textContent = hex(); }
    }, 900);
    const dz = $('#dropZone'), name = $('.dz-name'), st = $('#dzStatus');
    dz && dz.addEventListener('dragenter', (e) => {
        const it = e.dataTransfer && e.dataTransfer.items && e.dataTransfer.items[0];
        if (name && it && it.kind === 'file') name.textContent = 'incoming…';
        if (st) st.textContent = 'ARMED';
    });
    dz && dz.addEventListener('dragleave', () => { if (name) name.textContent = 'MyApp.apk'; if (st) st.textContent = 'READY'; });
}

/* ---------------- live byte counter ----------------
   The old "0 bytes uploaded" was a static claim. Now the landing shows
   real bytes this browser has scanned (persisted locally), while the
   upload count stays honestly at 0 B. */
const KEY_BYTES = 'uca.bytesScanned';
function fmtBytes(b) {
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; b = Number(b) || 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return (i ? b.toFixed(b < 10 ? 2 : 1) : Math.round(b)) + ' ' + u[i];
}
function bytesStats() { return readJSON(KEY_BYTES, { bytes: 0, files: 0 }); }
let counterRaf = 0;
function renderBytesCounter(animateFrom, nudge) {
    const el = $('#bytesAudited'), key = $('#bytesAuditedKey');
    if (!el) return;
    const st = bytesStats();
    if (key) key.textContent = (st.files ? st.files + ' file' + (st.files === 1 ? '' : 's') + ' scanned locally' : 'scanned locally') + ' · 0 B uploaded';
    const to = st.bytes || 0;
    const from = typeof animateFrom === 'number' ? animateFrom : to;
    cancelAnimationFrame(counterRaf);
    if (from === to || settings.reduceMotion) { el.textContent = fmtBytes(to); return; }
    const t0 = performance.now(), dur = 1100;
    const step = (t) => {
        const k = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - k, 3);
        el.textContent = fmtBytes(from + (to - from) * e);
        if (k < 1) counterRaf = requestAnimationFrame(step);
        else if (nudge) { el.classList.remove('bump'); void el.offsetWidth; el.classList.add('bump'); }
    };
    counterRaf = requestAnimationFrame(step);
}
function recordBytes(file) {
    if (!file || !file.size) return;
    const st = bytesStats();
    const before = st.bytes || 0;
    st.bytes = before + file.size; st.files = (st.files || 0) + 1;
    writeJSON(KEY_BYTES, st);
    renderBytesCounter(before, true);
}

/* ---------------- wiring ---------------- */
function onResults(e) {
    const { results, file, sample } = e.detail || {};
    if (!results) return;
    const pill = $('#samplePill'); if (pill) pill.hidden = !sample;
    if (!sample) baseline = baseline && baseline.auto ? null : baseline;
    renderChecklist(results);
    renderCategories(results);
    renderOwasp(results);
    renderHotFiles(results);
    renderHashes(results, file || null);
    renderDiff(results);
    if (!sample) { recordHistory(results); recordBytes(file); }
    expandIssues();
    const dzn = $('.dz-name'); if (dzn) dzn.textContent = (file && file.name) || 'MyApp.apk';
    const dzs = $('#dzStatus'); if (dzs) dzs.textContent = file && file.size ? 'READ ' + fmtBytes(file.size) : 'READY';
}

function init() {
    if (!UCA.State) { console.warn('[Unicollect] core UI not loaded'); return; }
    UCA.State.findingsPerPage = parseInt(settings.perPage, 10) || 50;
    setupSettings(); applySettings();
    setupOverlays(); setupPalette(); setupKeys(); setupExports(); setupBaseline(); setupByteWall();
    renderHistory();
    const kick = () => document.documentElement.classList.contains('site-ready') ? setTimeout(() => renderBytesCounter(0), 420) : setTimeout(kick, 120);
    renderBytesCounter(); kick();
    $('#sampleBtn') && $('#sampleBtn').addEventListener('click', openSample);
    $('#clearHistoryBtn') && $('#clearHistoryBtn').addEventListener('click', clearHistory);
    document.addEventListener('uca:results', onResults);
    const mark = $('.creator-mark');
    if (mark) {
        const tuck = () => mark.classList.toggle('is-tucked', window.scrollY > 80);
        window.addEventListener('scroll', tuck, { passive: true }); tuck();
    }
    const list = $('#findingsList');
    if (list && 'MutationObserver' in window) new MutationObserver(() => expandIssues()).observe(list, { childList: true });
    if (new URLSearchParams(location.search).get('sample') === '1') openSample();
}

UCA.openSample = openSample;
UCA.openPalette = openPalette;
window.UCA = UCA;

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
})();
