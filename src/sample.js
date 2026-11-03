/* Unicollect APK Auditor · built-in sample report.
   A fictional app ("Fieldnote") used to preview the UI without an APK.
   Every value below is synthetic; keys and tokens are well-known placeholders. */
(function (root) {
'use strict';

const PKG = 'com.unicollect.sample.fieldnote';

const files = [
    'AndroidManifest.xml', 'classes.dex', 'classes2.dex', 'resources.arsc',
    'META-INF/CERT.RSA', 'META-INF/CERT.SF', 'META-INF/MANIFEST.MF',
    'assets/config.json', 'assets/web/index.html', 'assets/web/bridge.js',
    'res/xml/network_security_config.xml', 'res/values/strings.xml',
    'res/layout/activity_main.xml', 'res/drawable/ic_launcher.xml',
    'lib/arm64-v8a/libsqlcipher.so', 'lib/arm64-v8a/libnative-lib.so',
    'lib/armeabi-v7a/libsqlcipher.so', 'lib/armeabi-v7a/libnative-lib.so',
    'kotlin/kotlin.kotlin_builtins', 'okhttp3/internal/publicsuffix/publicsuffixes.gz',
];

function tree(list) {
    const t = {};
    for (const path of list) {
        const parts = path.split('/');
        let cur = t;
        parts.forEach((p, i) => {
            if (i === parts.length - 1) cur[p] = { _type: 'file', _path: path, _size: 1024 + (path.length * 977) % 90000 };
            else { cur[p] = cur[p] || { _type: 'dir' }; cur = cur[p]; }
        });
    }
    return t;
}

const manifestStr = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="${PKG}" android:versionCode="4120" android:versionName="4.12.0">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="34" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <application android:label="Fieldnote" android:allowBackup="true"
        android:networkSecurityConfig="@xml/network_security_config"
        android:usesCleartextTraffic="true">
        <activity android:name=".ui.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".ui.DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="fieldnote" android:host="open" />
            </intent-filter>
        </activity>
        <activity android:name=".ui.SettingsActivity" android:exported="false" />
        <activity android:name=".web.WebShellActivity" android:exported="true" />
        <service android:name=".sync.SyncService" android:exported="false" />
        <service android:name=".push.PushService" android:exported="true"
            android:permission="com.google.android.c2dm.permission.SEND" />
        <receiver android:name=".boot.BootReceiver" android:exported="true">
            <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED" /></intent-filter>
        </receiver>
        <provider android:name=".data.NotesProvider" android:authorities="${PKG}.notes"
            android:exported="true" android:grantUriPermissions="true" />
        <provider android:name="androidx.core.content.FileProvider" android:authorities="${PKG}.files"
            android:exported="false" android:grantUriPermissions="true" />
    </application>
</manifest>`;

const fileContents = {
    'AndroidManifest.xml': manifestStr,
    'assets/config.json': JSON.stringify({
        env: 'production',
        api: 'http://api.fieldnote.example/v2',
        aws: { accessKeyId: 'AKIA' + 'IOSFODNN7' + 'EXAMPLE', region: 'eu-west-1' },
        stripe: { publishable: 'pk_' + 'test_' + 'TYooMQauvdEDq54NiTphI7jx' },
        featureFlags: { webBridge: true, offline: true },
    }, null, 2),
    'res/xml/network_security_config.xml': `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>`,
    'assets/web/bridge.js': `// Fieldnote web bridge (sample)
window.Fieldnote = window.Fieldnote || {};
Fieldnote.save = function (note) { return AndroidBridge.saveNote(JSON.stringify(note)); };
Fieldnote.token = function () { return AndroidBridge.getSessionToken(); };`,
    'res/values/strings.xml': `<resources>
    <string name="app_name">Fieldnote</string>
    <string name="google_api_key">AIza` + `SyD-EXAMPLE-0000000000000000000000</string>
    <string name="backend_url">http://api.fieldnote.example/v2</string>
</resources>`,
};

function F(o) {
    o.instances = o.instances || [];
    o.count = o.instances.length || 1;
    o.avgConfidence = o.avgConfidence || Math.round(o.instances.reduce((a, i) => a + (i.confidence || 70), 0) / Math.max(1, o.instances.length));
    o.category = o.category || 'other';
    return o;
}
function I(file, line, match, confidence, entropy) {
    return { file, line, match, confidence, confidenceLabel: confidence >= 85 ? 'high' : confidence >= 60 ? 'medium' : confidence >= 30 ? 'low' : 'noise', entropy };
}

const issue = [
    F({ ruleId: 'aws_access_key', ruleName: 'AWS Access Key ID', severity: 'issue', description: 'An AWS access key ID is embedded in the app package. Anyone who unzips the APK can read it. Move credentials server-side and rotate the key.', cwe: 'CWE-798', owasp: 'M1', masvs: 'STORAGE-14',
        instances: [I('assets/config.json', 5, 'AKIA' + 'IOSFODNN7' + 'EXAMPLE', 96, 3.68)] }),
    F({ ruleId: 'cleartext_traffic', ruleName: 'Cleartext Traffic Permitted', severity: 'issue', description: 'The network security config allows plain HTTP for every domain. Traffic can be read or modified on hostile networks.', cwe: 'CWE-319', owasp: 'M5', masvs: 'NETWORK-1',
        instances: [I('res/xml/network_security_config.xml', 3, 'cleartextTrafficPermitted="true"', 92), I('AndroidManifest.xml', 16, 'android:usesCleartextTraffic="true"', 90)] }),
    F({ ruleId: 'user_ca_trusted', ruleName: 'User-installed CAs Trusted', severity: 'issue', description: 'The app trusts user-added certificate authorities, which makes TLS interception trivial on a rooted or managed device.', cwe: 'CWE-295', owasp: 'M5', masvs: 'NETWORK-2',
        instances: [I('res/xml/network_security_config.xml', 6, '<certificates src="user" />', 88)] }),
    F({ ruleId: 'webview_js_interface', ruleName: 'WebView addJavascriptInterface', severity: 'issue', description: 'A Java object is exposed to JavaScript running in a WebView. Any page loaded there can call it, including getSessionToken().', cwe: 'CWE-749', owasp: 'M4', masvs: 'PLATFORM-7',
        instances: [I('com.unicollect.sample.fieldnote.web.WebShellActivity.java', 41, 'webView.addJavascriptInterface(new AndroidBridge(this), "AndroidBridge")', 84), I('assets/web/bridge.js', 4, 'AndroidBridge.getSessionToken()', 72)] }),
    F({ ruleId: 'webview_file_access', ruleName: 'WebView File Access Enabled', severity: 'issue', description: 'setAllowFileAccessFromFileURLs(true) lets local HTML read other local files.', cwe: 'CWE-200', owasp: 'M4', masvs: 'PLATFORM-6',
        instances: [I('com.unicollect.sample.fieldnote.web.WebShellActivity.java', 37, 'settings.setAllowFileAccessFromFileURLs(true)', 86)] }),
    F({ ruleId: 'exported_provider', ruleName: 'Exported ContentProvider Without Permission', severity: 'issue', description: 'NotesProvider is exported with no read or write permission. Any installed app can query user notes.', cwe: 'CWE-926', owasp: 'M8', masvs: 'PLATFORM-1',
        instances: [I('AndroidManifest.xml', 41, 'android:name=".data.NotesProvider" android:exported="true"', 90)] }),
    F({ ruleId: 'allow_backup', ruleName: 'android:allowBackup Enabled', severity: 'issue', description: 'App data can be extracted with adb backup on older Android versions.', cwe: 'CWE-530', owasp: 'M9', masvs: 'STORAGE-8',
        instances: [I('AndroidManifest.xml', 14, 'android:allowBackup="true"', 80)] }),
    F({ ruleId: 'weak_hash_md5', ruleName: 'Weak Hash: MD5', severity: 'issue', description: 'MD5 is broken for integrity and must not protect passwords or tokens.', cwe: 'CWE-328', owasp: 'M10', masvs: 'CRYPTO-4',
        instances: [I('com.unicollect.sample.fieldnote.auth.PinHasher.java', 22, 'MessageDigest.getInstance("MD5")', 78), I('com.unicollect.sample.fieldnote.sync.ETag.java', 9, 'MessageDigest.getInstance("MD5")', 52)] }),
    F({ ruleId: 'ecb_mode', ruleName: 'AES in ECB Mode', severity: 'issue', description: 'ECB leaks plaintext patterns. Use AES/GCM/NoPadding with a random IV.', cwe: 'CWE-327', owasp: 'M10', masvs: 'CRYPTO-2',
        instances: [I('com.unicollect.sample.fieldnote.data.LocalCrypto.java', 31, 'Cipher.getInstance("AES/ECB/PKCS5Padding")', 88)] }),
    F({ ruleId: 'google_api_key', ruleName: 'Google API Key', severity: 'issue', description: 'A Google API key is stored in string resources. Restrict it to the package and SHA-1 in Cloud Console.', cwe: 'CWE-798', owasp: 'M1', masvs: 'STORAGE-14',
        instances: [I('res/values/strings.xml', 3, 'AIza' + 'SyD-EXAMPLE-0000000000000000000000', 74, 4.1)] }),
    F({ ruleId: 'http_url', ruleName: 'Hardcoded HTTP Endpoint', severity: 'issue', description: 'Production API is referenced over plain HTTP.', cwe: 'CWE-319', owasp: 'M5', masvs: 'NETWORK-1',
        instances: [I('assets/config.json', 3, 'http://api.fieldnote.example/v2', 82), I('res/values/strings.xml', 4, 'http://api.fieldnote.example/v2', 82)] }),
];
const info = [
    F({ ruleId: 'dynamic_loading', ruleName: 'Dynamic Class Loading', severity: 'info', description: 'DexClassLoader is used. Make sure loaded code comes from a trusted, integrity-checked source.', cwe: 'CWE-94', owasp: 'M7', masvs: 'CODE-4',
        instances: [I('com.unicollect.sample.fieldnote.plugins.PluginHost.java', 58, 'new DexClassLoader(path, cacheDir, null, getClassLoader())', 64)] }),
    F({ ruleId: 'clipboard', ruleName: 'Clipboard Access', severity: 'info', description: 'Clipboard contents can be read by other apps on older Android versions.', cwe: 'CWE-200', owasp: 'M6', masvs: 'PLATFORM-9',
        instances: [I('com.unicollect.sample.fieldnote.ui.NoteEditor.java', 112, 'clipboardManager.setPrimaryClip(clip)', 58)] }),
    F({ ruleId: 'raw_sql', ruleName: 'Raw SQL Query', severity: 'info', description: 'rawQuery with string concatenation can lead to SQL injection if input is not bound.', cwe: 'CWE-89', owasp: 'M4', masvs: 'CODE-4',
        instances: [I('com.unicollect.sample.fieldnote.data.NotesDao.java', 77, 'db.rawQuery("SELECT * FROM notes WHERE tag = \'" + tag + "\'", null)', 66)] }),
];
const secure = [
    F({ ruleId: 'obfuscated', ruleName: 'Code Obfuscation Active', severity: 'secure', description: 'R8 obfuscation detected from class name analysis.', cwe: '', owasp: '', masvs: 'RESILIENCE-9',
        instances: [I('classes.dex', null, 'Short class names > 40% of total', 90)] }),
    F({ ruleId: 'flag_secure', ruleName: 'Screenshots Blocked (FLAG_SECURE)', severity: 'secure', description: 'Sensitive screens set FLAG_SECURE so they do not appear in screenshots or recents.', cwe: '', owasp: 'M6', masvs: 'PLATFORM-10',
        instances: [I('com.unicollect.sample.fieldnote.ui.LockActivity.java', 28, 'getWindow().setFlags(FLAG_SECURE, FLAG_SECURE)', 85)] }),
    F({ ruleId: 'sqlcipher', ruleName: 'Encrypted Database (SQLCipher)', severity: 'secure', description: 'Local notes database uses SQLCipher.', cwe: '', owasp: 'M9', masvs: 'STORAGE-2',
        instances: [I('lib/arm64-v8a/libsqlcipher.so', null, 'libsqlcipher.so', 92)] }),
];

const comp = (type, name, exported, extra) => Object.assign({ type, name: PKG + name, exported, permission: '', readPermission: '', writePermission: '', launchMode: '', taskAffinity: '', intentFilters: [] }, extra || {});

const results = {
    __sample: true,
    appInfo: {
        fileName: 'fieldnote-4.12.0-release.apk', fileSize: '18.4 MB',
        sha256: '3f1c9a7e52b04d6b8f0e2a91c47d5e6f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d',
        md5: '9e107d9d372bb6826bd81d3542a419d6',
        packageName: PKG, appLabel: 'Fieldnote', versionName: '4.12.0', versionCode: '4120',
        mainActivity: PKG + '.ui.MainActivity', allowBackup: true, debuggable: false,
        networkSecurityConfig: '@xml/network_security_config',
    },
    minSdk: 23, targetSdk: 34,
    permissions: [
        'android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.CAMERA',
        'android.permission.ACCESS_FINE_LOCATION', 'android.permission.READ_CONTACTS', 'android.permission.RECORD_AUDIO',
        'android.permission.POST_NOTIFICATIONS', 'android.permission.RECEIVE_BOOT_COMPLETED',
    ],
    dangerousPerms: ['android.permission.CAMERA', 'android.permission.ACCESS_FINE_LOCATION', 'android.permission.READ_CONTACTS', 'android.permission.RECORD_AUDIO', 'android.permission.POST_NOTIFICATIONS'],
    components: {
        activities: [
            comp('activity', '.ui.MainActivity', true, { intentFilters: [{ actions: ['android.intent.action.MAIN'], categories: ['android.intent.category.LAUNCHER'], data: [] }] }),
            comp('activity', '.ui.DeepLinkActivity', true, { intentFilters: [{ actions: ['android.intent.action.VIEW'], categories: ['android.intent.category.BROWSABLE'], data: [{ scheme: 'fieldnote', host: 'open' }] }] }),
            comp('activity', '.ui.SettingsActivity', false),
            comp('activity', '.web.WebShellActivity', true),
        ],
        services: [
            comp('service', '.sync.SyncService', false),
            comp('service', '.push.PushService', true, { permission: 'com.google.android.c2dm.permission.SEND' }),
        ],
        receivers: [
            comp('receiver', '.boot.BootReceiver', true, { intentFilters: [{ actions: ['android.intent.action.BOOT_COMPLETED'], categories: [], data: [] }] }),
        ],
        providers: [
            comp('provider', '.data.NotesProvider', true, { authorities: PKG + '.notes', grantUriPermissions: true }),
            Object.assign(comp('provider', '', false, { authorities: PKG + '.files', grantUriPermissions: true }), { name: 'androidx.core.content.FileProvider' }),
        ],
    },
    certInfo: {
        subject: { CN: 'Fieldnote Release', O: 'Unicollect Sample Co.', OU: 'Mobile' },
        issuer: { CN: 'Fieldnote Release', O: 'Unicollect Sample Co.' },
        serial: '5c2f81e0a93d4b17', sigAlg: 'SHA256withRSA',
        validity: { notBefore: '2024-03-02', notAfter: '2051-07-19' },
        isDebug: false, isExpired: false,
        fingerprintSHA256: 'A1:9F:0C:44:7B:E2:91:3D:58:6A:C0:FF:12:7E:B4:93:2C:D1:66:08:4E:AA:71:5B:39:C2:E8:0D:F4:16:9B:27',
    },
    hasV2Sig: true, isObfuscated: true,
    dexFiles: [{ name: 'classes.dex', classes: 6420, methods: 48211, strings: 61402 }, { name: 'classes2.dex', classes: 2318, methods: 17090, strings: 20511 }],
    nativeLibs: files.filter(f => f.endsWith('.so')),
    trackers: ['Firebase', 'Google Analytics', 'Google Ads (AdMob)', 'Facebook SDK', 'Sentry'],
    urls: [
        'http://api.fieldnote.example/v2', 'http://api.fieldnote.example/v2/notes', 'https://api.fieldnote.example/v2/auth',
        'https://cdn.fieldnote.example/assets/', 'https://firebaseinstallations.googleapis.com/v1/', 'https://app-measurement.com/a',
        'https://graph.facebook.com/v17.0/', 'https://o0.ingest.sentry.io/api/', 'http://schemas.android.com/apk/res/android',
    ],
    strings: [],
    files, fileTree: tree(files), fileContents, manifestStr,
    specialFiles: { dex: ['classes.dex', 'classes2.dex'], databases: [], configs: ['assets/config.json'] },
    groupedFindings: { issue, info, secure },
    summary: { issue: issue.length, info: info.length, secure: secure.length },
    securityScore: 41,
    warnings: [],
};
results.strings = results.urls.concat(['AndroidBridge', 'getSessionToken', 'AES/ECB/PKCS5Padding', 'MD5', 'fieldnote://open']);

root.UCA_SAMPLE = results;
})(typeof self !== 'undefined' ? self : this);
