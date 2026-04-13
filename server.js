import express from 'express';
import fetch from 'node-fetch';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import crypto from 'crypto';
import helmet from 'helmet';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// Encrypted Config System
// ============================================================
const CONFIG_PATH = process.env.VERCEL
  ? '/tmp/.config.enc'
  : join(__dirname, '.config.enc');
const CONFIG_ENCRYPTION_KEY = crypto.scryptSync('N00b-S3cret-K3y-2026!', 'salt-noob', 32);
const CONFIG_IV_LEN = 16;

// Admin access key — use this in URL: /admin?key=YOUR_KEY
const ADMIN_KEY = 'xK9mW2pL7qR4vT8n';

const DEFAULT_CONFIG = {
  apiUrl: 'https://api.iprn-elite.com/v1.0',
  apiKey: '9pS-fYdnRrqNvELaRAdTEg',
  trunkId: 'tI07q2E-R5-PYafpI9jyIg',
  proxyUrl: 'http://65.181.123.105:3128',
};

function encryptConfig(data) {
  const iv = crypto.randomBytes(CONFIG_IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-cbc', CONFIG_ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptConfig(raw) {
  const parts = raw.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv('aes-256-cbc', CONFIG_ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
      return decryptConfig(raw);
    }
  } catch (err) {
    console.error('Config load error, using defaults:', err.message);
  }
  // Save defaults on first run
  saveConfig(DEFAULT_CONFIG);
  return { ...DEFAULT_CONFIG };
}

function saveConfig(data) {
  const encrypted = encryptConfig(data);
  fs.writeFileSync(CONFIG_PATH, encrypted, 'utf8');
}

// Load config into memory
let config = loadConfig();

function getConfig() {
  return config;
}

// ============================================================
// Security: Session tokens
// ============================================================
const TOKEN_SECRET = crypto.randomBytes(32).toString('hex');
const validTokens = new Map();
const TOKEN_TTL = 5 * 60 * 1000;

function generateToken() {
  const token = crypto.randomBytes(32).toString('hex');
  const hmac = crypto.createHmac('sha256', TOKEN_SECRET).update(token).digest('hex');
  validTokens.set(hmac, { created: Date.now() });
  return hmac;
}

function validateToken(token) {
  if (!token || typeof token !== 'string') return false;
  const entry = validTokens.get(token);
  if (!entry) return false;
  if (Date.now() - entry.created > TOKEN_TTL) {
    validTokens.delete(token);
    return false;
  }
  validTokens.delete(token);
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of validTokens) {
    if (now - val.created > TOKEN_TTL) validTokens.delete(key);
  }
}, 60 * 1000);

// ============================================================
// Security: Rate limiting
// ============================================================
const rateLimitMap = new Map();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60 * 1000;

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW) {
    rateLimitMap.set(ip, { start: now, count: 1 });
    return true;
  }
  entry.count++;
  return entry.count <= RATE_LIMIT;
}

// ============================================================
// Admin session tokens (separate from CSRF tokens)
// ============================================================
const adminSessions = new Map();
const ADMIN_SESSION_TTL = 15 * 60 * 1000; // 15 minutes

function createAdminSession() {
  const sid = crypto.randomBytes(32).toString('hex');
  adminSessions.set(sid, { created: Date.now() });
  return sid;
}

function validateAdminSession(sid) {
  if (!sid) return false;
  const entry = adminSessions.get(sid);
  if (!entry) return false;
  if (Date.now() - entry.created > ADMIN_SESSION_TTL) {
    adminSessions.delete(sid);
    return false;
  }
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of adminSessions) {
    if (now - val.created > ADMIN_SESSION_TTL) adminSessions.delete(key);
  }
}, 60 * 1000);

// ============================================================
// Middleware
// ============================================================
app.use((req, res, next) => {
  // Generate a nonce for each request
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use((req, res, next) => {
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", `'nonce-${res.locals.cspNonce}'`],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    referrerPolicy: { policy: 'no-referrer' },
  })(req, res, next);
});

app.use((req, res, next) => {
  if (req.method === 'POST') {
    const origin = req.get('origin');
    const host = req.get('host');
    if (origin && host && !origin.includes(host)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  }
  res.removeHeader('X-Powered-By');
  next();
});

app.use(express.json());
app.use(express.static(join(__dirname, 'public')));

// ============================================================
// Admin routes
// ============================================================

// Admin page — requires ?key=ADMIN_KEY
app.get('/admin', (req, res) => {
  if (req.query.key !== ADMIN_KEY) {
    return res.status(404).send('Not found');
  }
  const sid = createAdminSession();
  const nonce = res.locals.cspNonce;
  res.send(getAdminHTML(sid, nonce));
});

// Get current config (admin only)
app.get('/api/admin/config', (req, res) => {
  const sid = req.headers['x-admin-session'];
  if (!validateAdminSession(sid)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  const c = getConfig();
  // Mask sensitive values for display
  res.json({
    apiUrl: c.apiUrl,
    apiKey: maskValue(c.apiKey),
    trunkId: maskValue(c.trunkId),
    proxyUrl: c.proxyUrl,
  });
});

// Update config (admin only)
app.post('/api/admin/config', (req, res) => {
  const sid = req.headers['x-admin-session'];
  if (!validateAdminSession(sid)) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { apiUrl, apiKey, trunkId, proxyUrl } = req.body;
  const current = getConfig();

  // Only update fields that were provided and not empty
  if (apiUrl && typeof apiUrl === 'string' && apiUrl.startsWith('https://')) {
    current.apiUrl = apiUrl.trim();
  }
  if (apiKey && typeof apiKey === 'string' && apiKey.length > 5 && !apiKey.includes('*')) {
    current.apiKey = apiKey.trim();
  }
  if (trunkId && typeof trunkId === 'string' && trunkId.length > 5 && !trunkId.includes('*')) {
    current.trunkId = trunkId.trim();
  }
  if (proxyUrl && typeof proxyUrl === 'string') {
    current.proxyUrl = proxyUrl.trim();
  }

  saveConfig(current);
  config = current;

  res.json({ success: true, message: 'Configuration updated.' });
});

function maskValue(str) {
  if (!str || str.length < 6) return '****';
  return str.substring(0, 3) + '*'.repeat(str.length - 6) + str.substring(str.length - 3);
}

// ============================================================
// Public API routes
// ============================================================
app.get('/api/token', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }
  res.json({ token: generateToken() });
});

app.post('/api/fetch-numbers', async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }

  const token = req.headers['x-csrf-token'];
  if (!validateToken(token)) {
    return res.status(403).json({ error: 'Invalid or expired session. Refresh the page.' });
  }

  const { template, numbers } = req.body;

  if (!template || typeof template !== 'string' || template.trim() === '') {
    return res.status(400).json({ error: 'Template (number range) is required.' });
  }

  const count = parseInt(numbers, 10);
  if (isNaN(count) || count < 1 || count > 50) {
    return res.status(400).json({ error: 'Numbers must be between 1 and 50.' });
  }

  const c = getConfig();
  const agent = new HttpsProxyAgent(c.proxyUrl);

  const payload = {
    id: null,
    jsonrpc: '2.0',
    method: 'allocation:template_by_account_user',
    params: {
      target: { trunk_id: c.trunkId },
      numbers: count,
      random_number: true,
      template: template.trim(),
    },
  };

  try {
    const response = await fetch(c.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Api-Key': c.apiKey },
      body: JSON.stringify(payload),
      agent,
    });

    const data = await response.json();

    if (data.error) {
      return res.json(data);
    }

    const transactionId = data.result?.trunk_number_transaction?.id;
    if (!transactionId) {
      return res.status(502).json({ error: 'No transaction ID returned from allocation.' });
    }

    const listPayload = {
      id: null,
      jsonrpc: '2.0',
      method: 'trunk_number:get_list',
      params: { target: { trunk_number_transaction_id: transactionId } },
    };

    const listResponse = await fetch(c.apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Api-Key': c.apiKey },
      body: JSON.stringify(listPayload),
      agent,
    });

    const listData = await listResponse.json();
    const numberList = listData.result?.trunk_number_list || [];
    const cleanNumbers = numberList.map(item => ({ number: item.number }));
    res.json({ numbers: { result: { trunk_number_list: cleanNumbers } } });
  } catch (err) {
    console.error('API request failed:', err.message);
    res.status(502).json({ error: 'Something went wrong. Please try again.' });
  }
});

// ============================================================
// Admin HTML (served inline, no file on disk)
// ============================================================
function getAdminHTML(sessionId, nonce) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Inter', sans-serif;
      background: #f8f8f8;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #1a1a1a;
    }
    .panel {
      background: #fff;
      border: 1px solid #e8e8e8;
      border-radius: 20px;
      padding: 40px;
      width: 100%;
      max-width: 520px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.06);
    }
    h1 {
      font-size: 1.3rem;
      font-weight: 700;
      margin-bottom: 8px;
    }
    .subtitle {
      font-size: 0.8rem;
      color: #999;
      margin-bottom: 28px;
    }
    .field { margin-bottom: 18px; }
    .field label {
      display: block;
      font-size: 0.75rem;
      font-weight: 600;
      color: #888;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
    .field input {
      width: 100%;
      padding: 12px 14px;
      border: 1px solid #e0e0e0;
      border-radius: 10px;
      background: #fafafa;
      font-family: 'SF Mono', 'Courier New', monospace;
      font-size: 0.88rem;
      color: #333;
      outline: none;
      transition: border-color 0.2s;
    }
    .field input:focus {
      border-color: #7c4dff;
      box-shadow: 0 0 0 3px rgba(124,77,255,0.1);
    }
    .field input::placeholder { color: #ccc; }
    .save-btn {
      width: 100%;
      padding: 14px;
      border: none;
      border-radius: 10px;
      background: #7c4dff;
      color: #fff;
      font-family: 'Inter', sans-serif;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      margin-top: 6px;
      transition: all 0.2s;
    }
    .save-btn:hover { background: #6a3de8; }
    .save-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .msg {
      margin-top: 16px;
      padding: 12px 16px;
      border-radius: 8px;
      font-size: 0.85rem;
      display: none;
    }
    .msg.success { display: block; background: #f0fff4; border: 1px solid #c6f6d5; color: #2f855a; }
    .msg.error { display: block; background: #fff5f5; border: 1px solid #ffe0e0; color: #e53e3e; }
    .lock-icon { font-size: 0.85rem; margin-right: 4px; }
  </style>
</head>
<body>
  <div class="panel">
    <h1><span class="lock-icon">&#128274;</span> Admin Panel</h1>
    <p class="subtitle">Update API settings and proxy. Leave blank to keep current value.</p>

    <div class="field">
      <label>API URL</label>
      <input type="text" id="apiUrl" placeholder="Loading...">
    </div>
    <div class="field">
      <label>API Key</label>
      <input type="text" id="apiKey" placeholder="Loading...">
    </div>
    <div class="field">
      <label>Trunk ID</label>
      <input type="text" id="trunkId" placeholder="Loading...">
    </div>
    <div class="field">
      <label>Proxy URL</label>
      <input type="text" id="proxyUrl" placeholder="Loading...">
    </div>

    <button class="save-btn" id="saveBtn">Save Changes</button>
    <div class="msg" id="msg"></div>
  </div>

  <script nonce="${nonce}">
    var SID = '${sessionId}';
    var apiUrlInput = document.getElementById('apiUrl');
    var apiKeyInput = document.getElementById('apiKey');
    var trunkIdInput = document.getElementById('trunkId');
    var proxyUrlInput = document.getElementById('proxyUrl');
    var saveBtn = document.getElementById('saveBtn');
    var msgEl = document.getElementById('msg');

    // Load current config
    fetch('/api/admin/config', { headers: { 'X-Admin-Session': SID } })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.error) { showMsg('error', data.error); return; }
      apiUrlInput.value = data.apiUrl || '';
      apiKeyInput.value = data.apiKey || '';
      trunkIdInput.value = data.trunkId || '';
      proxyUrlInput.value = data.proxyUrl || '';
      apiUrlInput.placeholder = 'https://...';
      apiKeyInput.placeholder = 'Enter new key to change';
      trunkIdInput.placeholder = 'Enter new ID to change';
      proxyUrlInput.placeholder = 'http://ip:port';
    })
    .catch(function() { showMsg('error', 'Failed to load config.'); });

    saveBtn.addEventListener('click', function() {
      saveBtn.disabled = true;
      msgEl.className = 'msg';
      msgEl.style.display = 'none';

      var body = {};
      if (apiUrlInput.value.trim()) body.apiUrl = apiUrlInput.value.trim();
      if (apiKeyInput.value.trim()) body.apiKey = apiKeyInput.value.trim();
      if (trunkIdInput.value.trim()) body.trunkId = trunkIdInput.value.trim();
      if (proxyUrlInput.value.trim()) body.proxyUrl = proxyUrlInput.value.trim();

      fetch('/api/admin/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Admin-Session': SID },
        body: JSON.stringify(body),
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.success) {
          showMsg('success', 'Settings saved successfully.');
        } else {
          showMsg('error', data.error || 'Save failed.');
        }
      })
      .catch(function() { showMsg('error', 'Network error.'); })
      .finally(function() { saveBtn.disabled = false; });
    });

    function showMsg(type, text) {
      msgEl.className = 'msg ' + type;
      msgEl.textContent = text;
      msgEl.style.display = 'block';
    }
  </script>
</body>
</html>`;
}

// Only listen when running directly (not on Vercel)
if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin?key=${ADMIN_KEY}`);
  });
}

// Export for Vercel serverless
export default app;
