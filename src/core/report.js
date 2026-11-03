/* Unicollect APK Auditor · Markdown, HTML and plain-text summary reports. */
(function (root) {
'use strict';

const TOOL = 'Unicollect APK Auditor';
const VERSION = '1.0.0';
const CREATOR = 'muvixo';

function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function mdEsc(s) { return String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' '); }
function tick(s) { const v = String(s == null ? '' : s).replace(/`/g, 'ˋ'); return '`' + v + '`'; }

function groups(r) {
    const g = r.groupedFindings || {};
    return { issue: g.issue || [], info: g.info || [], secure: g.secure || [] };
}
function scoreLabel(score) {
    return score >= 85 ? 'Excellent' : score >= 70 ? 'Good' : score >= 50 ? 'Fair' : score >= 30 ? 'Poor' : 'Critical';
}
function trackerNames(r) { return (r.trackers || []).map(t => typeof t === 'string' ? t : (t && t.name) || '').filter(Boolean); }
function allComponents(r) {
    const c = r.components || {};
    return [].concat(c.activities || [], c.services || [], c.receivers || [], c.providers || []);
}

/* hardening checks shared by the Insights tab and the reports */
function hardening(r) {
    const ai = r.appInfo || {};
    const cert = r.certInfo || null;
    const all = [].concat(groups(r).issue);
    const has = (re) => all.some(f => re.test((f.ruleId || '') + ' ' + (f.ruleName || '')));
    const comps = allComponents(r);
    const openExported = comps.filter(c => c.exported && !c.permission && !c.readPermission && !c.writePermission && !/MainActivity$/.test(c.name || ''));
    const hasV1 = (r.files || []).some(f => /^META-INF\/.*\.SF$/i.test(f));
    const items = [
        { id: 'debuggable', name: 'Not debuggable', desc: 'android:debuggable is off in the shipped build.', pass: ai.debuggable === undefined ? null : !ai.debuggable },
        { id: 'backup', name: 'Backups restricted', desc: 'android:allowBackup is false, or backup rules are scoped.', pass: ai.allowBackup === undefined ? null : !ai.allowBackup },
        { id: 'cleartext', name: 'No cleartext traffic', desc: 'No plain-HTTP allowance in manifest or network config.', pass: !has(/cleartext|http_url|insecure_http/i) },
        { id: 'nsc', name: 'Network security config', desc: 'A network_security_config.xml is declared.', pass: ai.networkSecurityConfig === undefined ? null : !!ai.networkSecurityConfig },
        { id: 'v2', name: 'v2+ APK signature', desc: 'APK Signing Block present (blocks Janus on Android < 7).', pass: (r.hasV2Sig === undefined) ? null : (!!r.hasV2Sig || !hasV1) },
        { id: 'cert', name: 'Release certificate', desc: 'Not a debug key, not expired, strong algorithm.', pass: cert ? !(cert.isDebug || cert.isExpired || /MD5|SHA1withRSA/i.test(cert.sigAlg || '')) : null },
        { id: 'obf', name: 'Code obfuscated', desc: 'R8 / ProGuard renaming detected.', pass: r.isObfuscated === undefined ? null : !!r.isObfuscated },
        { id: 'target', name: 'Modern targetSdk', desc: 'targetSdkVersion is 33 or higher.', pass: r.targetSdk ? Number(r.targetSdk) >= 33 : null },
        { id: 'min', name: 'Sane minSdk', desc: 'minSdkVersion is 24 or higher (Android 7+).', pass: r.minSdk ? Number(r.minSdk) >= 24 : null },
        { id: 'exported', name: 'Exported components guarded', desc: openExported.length ? openExported.length + ' exported without a permission.' : 'Every exported component needs a permission.', pass: comps.length ? openExported.length === 0 : null },
        { id: 'secrets', name: 'No hardcoded secrets', desc: 'No vendor keys, tokens or private keys in the package.', pass: !has(/key|secret|token|jwt|pem|password|credential/i) },
        { id: 'crypto', name: 'Strong crypto', desc: 'No MD5 / SHA-1 / DES / RC4 / ECB usage.', pass: !has(/(^|[^a-z])(md5|sha-?1|des|3des|rc4|ecb)([^a-z]|$)|weak_(hash|cipher|crypto)/i) },
    ];
    const scored = items.filter(i => i.pass !== null);
    return { items, passed: scored.filter(i => i.pass).length, total: scored.length };
}

function summaryText(r) {
    const ai = r.appInfo || {};
    const s = r.summary || {};
    const g = groups(r);
    const h = hardening(r);
    const L = [];
    L.push(TOOL + ' · ' + (ai.appLabel || ai.packageName || ai.fileName || 'APK'));
    L.push('Package: ' + (ai.packageName || '-') + '  v' + (ai.versionName || '-') + ' (' + (ai.versionCode || '-') + ')');
    L.push('Score: ' + (r.securityScore != null ? r.securityScore : '-') + '/100 (' + scoreLabel(r.securityScore || 0) + ')');
    L.push('Findings: ' + (s.issue || 0) + ' issues · ' + (s.info || 0) + ' info · ' + (s.secure || 0) + ' secure');
    L.push('Hardening: ' + h.passed + '/' + h.total + ' checks passed');
    if (g.issue.length) {
        L.push('');
        L.push('Top issues:');
        g.issue.slice(0, 8).forEach(f => L.push('  - ' + f.ruleName + ' (' + (f.instances || []).length + 'x' + (f.cwe ? ', ' + f.cwe : '') + ')'));
    }
    const t = trackerNames(r);
    if (t.length) { L.push(''); L.push('Trackers: ' + t.join(', ')); }
    if (ai.sha256) { L.push(''); L.push('SHA-256: ' + ai.sha256); }
    L.push(''); L.push('Created by ' + CREATOR);
    return L.join('\n');
}

function toMarkdown(r) {
    const ai = r.appInfo || {};
    const s = r.summary || {};
    const g = groups(r);
    const h = hardening(r);
    const L = [];
    L.push('# 🛡️ ' + mdEsc(ai.appLabel || ai.packageName || 'APK') + ' · security audit');
    L.push('');
    L.push('> Generated by **' + TOOL + ' ' + VERSION + '** on ' + new Date().toISOString() + '. Static analysis only.');
    L.push('');
    L.push('| | |');
    L.push('|---|---|');
    L.push('| **Score** | **' + (r.securityScore != null ? r.securityScore : '-') + ' / 100** (' + scoreLabel(r.securityScore || 0) + ') |');
    L.push('| Package | ' + tick(ai.packageName || '-') + ' |');
    L.push('| Version | ' + mdEsc(ai.versionName || '-') + ' (' + mdEsc(ai.versionCode || '-') + ') |');
    L.push('| SDK | min ' + (r.minSdk || '-') + ' · target ' + (r.targetSdk || '-') + ' |');
    L.push('| File | ' + tick(ai.fileName || '-') + ' · ' + mdEsc(ai.fileSize || '') + ' |');
    if (ai.sha256) L.push('| SHA-256 | ' + tick(ai.sha256) + ' |');
    L.push('| Findings | 🔴 ' + (s.issue || 0) + ' issues · ⚪ ' + (s.info || 0) + ' info · 🔵 ' + (s.secure || 0) + ' secure |');
    L.push('');
    L.push('## ✅ Hardening checklist (' + h.passed + '/' + h.total + ')');
    L.push('');
    h.items.forEach(i => L.push('- ' + (i.pass === null ? '➖' : i.pass ? '✅' : '❌') + ' **' + i.name + '** · ' + mdEsc(i.desc)));
    L.push('');
    const section = (title, list) => {
        if (!list.length) return;
        L.push('## ' + title);
        L.push('');
        list.forEach(f => {
            L.push('### ' + mdEsc(f.ruleName));
            const tags = [f.cwe, f.owasp && ('OWASP ' + f.owasp), f.masvs && ('MASVS ' + f.masvs)].filter(Boolean).map(tick).join(' ');
            L.push('');
            L.push((tags ? tags + ' · ' : '') + 'confidence ' + (f.avgConfidence || 0) + '%');
            L.push('');
            if (f.description) { L.push(mdEsc(f.description)); L.push(''); }
            const inst = (f.instances || []).slice(0, 10);
            if (inst.length) {
                L.push('| # | Location | Match |');
                L.push('|---|---|---|');
                inst.forEach((it, j) => L.push('| ' + (j + 1) + ' | ' + tick((it.file || '') + (it.line ? ':' + it.line : '')) + ' | ' + tick(String(it.match || '').slice(0, 160)) + ' |'));
                if ((f.instances || []).length > inst.length) L.push('| … | ' + ((f.instances.length - inst.length)) + ' more | |');
                L.push('');
            }
        });
    };
    section('🔴 Issues', g.issue);
    section('⚪ Informational', g.info);
    section('🔵 Secure practices', g.secure);
    const t = trackerNames(r);
    if (t.length) { L.push('## 📡 Trackers & SDKs'); L.push(''); L.push(t.map(tick).join(' · ')); L.push(''); }
    const dp = r.dangerousPerms || [];
    if (dp.length) { L.push('## 🔑 Dangerous permissions'); L.push(''); dp.forEach(p => L.push('- ' + tick(p))); L.push(''); }
    const exp = allComponents(r).filter(c => c.exported);
    if (exp.length) {
        L.push('## 🧩 Exported components');
        L.push('');
        L.push('| Type | Name | Permission |');
        L.push('|---|---|---|');
        exp.forEach(c => L.push('| ' + c.type + ' | ' + tick(c.name) + ' | ' + (c.permission || c.readPermission || c.writePermission ? tick(c.permission || c.readPermission || c.writePermission) : '**none**') + ' |'));
        L.push('');
    }
    L.push('---');
    L.push('_For authorized security testing only. Created by **' + CREATOR + '**._');
    return L.join('\n');
}

function toHTML(r) {
    const ai = r.appInfo || {};
    const s = r.summary || {};
    const g = groups(r);
    const h = hardening(r);
    const score = r.securityScore != null ? r.securityScore : 0;
    const scoreColor = score >= 70 ? '#1F5BFF' : score >= 50 ? '#05070A' : score >= 30 ? '#A86A00' : '#D92D3F';
    const sev = { issue: ['ISSUE', '#D92D3F', '#fff'], info: ['INFO', '#EDF0F5', '#3D4555'], secure: ['SECURE', '#1F5BFF', '#fff'] };
    const findingHtml = (f) => {
        const [lbl, bg, fg] = sev[f.severity] || sev.info;
        const tags = [f.cwe, f.owasp && 'OWASP ' + f.owasp, f.masvs && 'MASVS ' + f.masvs].filter(Boolean).map(t => '<span class="tag">' + esc(t) + '</span>').join('');
        const inst = (f.instances || []).slice(0, 25).map((it, j) =>
            '<tr><td class="n">' + (j + 1) + '</td><td class="loc">' + esc((it.file || '') + (it.line ? ':' + it.line : '')) + '</td><td><code>' + esc(String(it.match || '').slice(0, 300)) + '</code></td></tr>').join('');
        return '<details class="f f-' + esc(f.severity) + '"' + (f.severity === 'issue' ? ' open' : '') + '><summary><span class="sev" style="background:' + bg + ';color:' + fg + '">' + lbl + '</span><span class="ft">' + esc(f.ruleName) + '</span><span class="fc">' + (f.instances || []).length + '×</span></summary>' +
            '<div class="fb"><p>' + esc(f.description || '') + '</p><div class="tags">' + tags + '<span class="tag">confidence ' + (f.avgConfidence || 0) + '%</span></div>' +
            (inst ? '<table><thead><tr><th>#</th><th>Location</th><th>Match</th></tr></thead><tbody>' + inst + '</tbody></table>' : '') + '</div></details>';
    };
    const kv = [
        ['Package', ai.packageName], ['Version', (ai.versionName || '-') + ' (' + (ai.versionCode || '-') + ')'],
        ['Min / target SDK', (r.minSdk || '-') + ' / ' + (r.targetSdk || '-')], ['File', (ai.fileName || '-') + ' · ' + (ai.fileSize || '')],
        ['Signature', r.certInfo ? ((r.certInfo.subject && (r.certInfo.subject.CN || r.certInfo.subject.O)) || '-') + ' · ' + (r.certInfo.sigAlg || '') : 'not found'],
        ['SHA-256', ai.sha256],
    ].filter(x => x[1]);
    const checks = h.items.map(i => '<li class="' + (i.pass === null ? 'na' : i.pass ? 'ok' : 'no') + '"><b>' + (i.pass === null ? '–' : i.pass ? '✓' : '✕') + '</b><div><strong>' + esc(i.name) + '</strong><span>' + esc(i.desc) + '</span></div></li>').join('');
    const trackers = trackerNames(r).map(t => '<span class="chip">' + esc(t) + '</span>').join('');
    const perms = (r.dangerousPerms || []).map(p => '<span class="chip red">' + esc(p.replace('android.permission.', '')) + '</span>').join('');
    const css = `
*{box-sizing:border-box;margin:0;padding:0}body{font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,'Segoe UI',sans-serif;color:#05070A;background:#fff;-webkit-font-smoothing:antialiased}
.wrap{max-width:980px;margin:0 auto;padding:48px 28px 80px}header{display:flex;align-items:center;gap:14px;margin-bottom:40px}
.mark{width:40px;height:40px}.brand{font-weight:700;letter-spacing:-.02em}.brand span{color:#C2410C;font-weight:500}.date{margin-left:auto;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:#6B7383}
h1{font-size:56px;line-height:.95;letter-spacing:-.05em;margin-bottom:10px}h1 i{font-style:normal;color:#E8590C}.pkg{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;color:#6B7383;margin-bottom:36px}
.top{display:grid;grid-template-columns:220px 1fr;gap:16px;margin-bottom:40px}.score{background:#05070A;color:#fff;border-radius:18px;padding:22px;display:flex;flex-direction:column;justify-content:space-between}
.score b{font-size:72px;letter-spacing:-.05em;line-height:1}.score small{opacity:.6}.score .lbl{font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}
.counts{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.count{border:1px solid #E3E7EE;border-radius:14px;padding:18px}.count b{display:block;font-size:40px;letter-spacing:-.04em;line-height:1}.count span{font-size:13px;color:#6B7383}
.kv{grid-column:1/-1;display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.kv div{background:#F5F7FA;border-radius:10px;padding:10px 14px}.kv label{display:block;font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:#6B7383;font-weight:600}.kv code{font-size:12.5px;word-break:break-all}
h2{font-size:24px;letter-spacing:-.03em;margin:44px 0 14px;display:flex;align-items:baseline;gap:10px}h2 small{font-size:13px;color:#6B7383;font-weight:500;letter-spacing:0}
.checks{list-style:none;display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.checks li{display:flex;gap:12px;padding:12px;border:1px solid #E3E7EE;border-radius:12px}.checks b{width:24px;height:24px;border-radius:7px;display:grid;place-items:center;flex-shrink:0;font-size:13px}
.checks .ok b{background:#1F5BFF;color:#fff}.checks .no b{background:#D92D3F;color:#fff}.checks .na b{background:#EDF0F5;color:#6B7383}.checks strong{display:block;font-size:14px}.checks span{font-size:12.5px;color:#6B7383}
details.f{border:1px solid #E3E7EE;border-left:3px solid #C9CFD9;border-radius:12px;margin-bottom:8px;overflow:hidden}details.f-issue{border-left-color:#D92D3F}details.f-secure{border-left-color:#1F5BFF}
summary{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;list-style:none}summary::-webkit-details-marker{display:none}.sev{font:700 10px ui-monospace,monospace;letter-spacing:.08em;padding:3px 8px;border-radius:5px}
.ft{flex:1;font-weight:600}.fc{font:12px ui-monospace,monospace;color:#6B7383}.fb{padding:0 16px 16px;border-top:1px solid #EEF1F5}.fb p{padding:12px 0;color:#3D4555;font-size:14px}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}.tag{font:11px ui-monospace,monospace;padding:3px 8px;border-radius:5px;background:rgba(31,91,255,.08);color:#1F5BFF}
table{width:100%;border-collapse:collapse;font-size:12.5px}th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.08em;color:#6B7383;padding:8px;border-bottom:1px solid #E3E7EE}
td{padding:8px;border-bottom:1px solid #F0F2F6;vertical-align:top;word-break:break-all}td.n{width:32px;color:#6B7383}td.loc{width:38%;font-family:ui-monospace,monospace;color:#1F5BFF;font-size:12px}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{font-size:12.5px;padding:5px 10px;border-radius:7px;border:1px solid #E3E7EE}.chip.red{color:#D92D3F;border-color:rgba(217,45,63,.35);background:rgba(217,45,63,.06)}
footer{margin-top:56px;padding-top:18px;border-top:1px solid #E3E7EE;font-size:12px;color:#6B7383;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
@media (max-width:720px){.top{grid-template-columns:1fr}.kv,.checks{grid-template-columns:1fr}h1{font-size:40px}}
@media print{details.f{break-inside:avoid}details:not([open]) .fb{display:block}}`;
    const mark = '<svg class="mark" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg"><rect x="1" y="1" width="62" height="62" rx="15" fill="#05070A"/><path d="M20 15.5V33a12 12 0 0 0 24 0V15.5" fill="none" stroke="#fff" stroke-width="7" stroke-linecap="round"/><rect x="9" y="28.5" width="46" height="8" fill="#05070A"/><rect x="9" y="30.5" width="46" height="4" rx="2" fill="#1F5BFF"/><circle cx="50.5" cy="14" r="3.5" fill="#1F5BFF"/></svg>';
    return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">' +
        '<title>' + esc((ai.appLabel || ai.packageName || 'APK') + ' · ' + TOOL) + '</title><style>' + css + '</style></head><body><div class="wrap">' +
        '<header>' + mark + '<div class="brand">Unicollect <span>APK Auditor</span></div><div class="date">' + esc(new Date().toISOString()) + '</div></header>' +
        '<h1>' + esc(ai.appLabel || ai.packageName || 'APK') + '<i>.</i></h1><div class="pkg">' + esc(ai.packageName || ai.fileName || '') + '</div>' +
        '<section class="top"><div class="score"><span class="lbl" style="color:' + (score >= 50 ? '#6E9BFF' : scoreColor) + '">' + scoreLabel(score) + '</span><div><b>' + score + '</b><small> / 100</small></div></div>' +
        '<div class="counts"><div class="count"><b style="color:#D92D3F">' + (s.issue || 0) + '</b><span>issues</span></div><div class="count"><b>' + (s.info || 0) + '</b><span>info</span></div><div class="count"><b style="color:#1F5BFF">' + (s.secure || 0) + '</b><span>secure</span></div></div>' +
        '<div class="kv">' + kv.map(([k, v]) => '<div><label>' + esc(k) + '</label><code>' + esc(v) + '</code></div>').join('') + '</div></section>' +
        '<h2>Hardening checklist <small>' + h.passed + ' / ' + h.total + ' passed</small></h2><ul class="checks">' + checks + '</ul>' +
        (g.issue.length ? '<h2>Issues <small>' + g.issue.length + ' rules</small></h2>' + g.issue.map(findingHtml).join('') : '') +
        (g.info.length ? '<h2>Informational <small>' + g.info.length + ' rules</small></h2>' + g.info.map(findingHtml).join('') : '') +
        (g.secure.length ? '<h2>Secure practices <small>' + g.secure.length + ' rules</small></h2>' + g.secure.map(findingHtml).join('') : '') +
        (perms ? '<h2>Dangerous permissions</h2><div class="chips">' + perms + '</div>' : '') +
        (trackers ? '<h2>Trackers &amp; SDKs</h2><div class="chips">' + trackers + '</div>' : '') +
        '<footer><span>' + TOOL + ' ' + VERSION + ' · static analysis, generated locally</span><span>Created by <b>' + CREATOR + '</b> · For authorized security testing only</span></footer>' +
        '</div></body></html>';
}

function download(text, filename, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(a.href); }, 1000);
}
function baseName(r) {
    const ai = r.appInfo || {};
    return (ai.packageName || (ai.fileName || 'apk').replace(/\.apk$/i, '')).replace(/[^a-zA-Z0-9._-]/g, '_');
}
function exportReport(kind, r) {
    if (kind === 'md') return download(toMarkdown(r), baseName(r) + '_report.md', 'text/markdown');
    if (kind === 'html') return download(toHTML(r), baseName(r) + '_report.html', 'text/html');
    throw new Error('Unknown report kind: ' + kind);
}

const api = { toMarkdown, toHTML, summaryText, hardening, exportReport, scoreLabel, trackerNames };
if (typeof module !== 'undefined' && module.exports) module.exports = api;
else { root.IPAA = root.IPAA || {}; root.IPAA.Report = api; }
})(typeof self !== 'undefined' ? self : this);
