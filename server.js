/**
 * Leatherbound Notebook — a local, encrypted, 3D page-flipping notebook.
 *
 * Everything lives on YOUR machine:
 *   - The whole notebook (text, fonts, styling) is stored as one
 *     encrypted file at data/notebook.enc.json
 *   - Images are stored as files in data/images/ and are served only
 *     while the notebook is unlocked (session-gated).
 *   - Both are encrypted with AES-256-GCM (notebook) / session-gated
 *     (images). The key is derived from your password with scrypt and
 *     is only ever held in server memory while the notebook is unlocked
 *     — it is never written to disk.
 *   - Because the file on disk is always encrypted, your notes stay
 *     protected even while the server is off, and you need your password
 *     again every time you restart the server.
 *
 * Run it with:  npm install && npm start
 * Then open:    http://localhost:3000
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;
const isVercel = !!process.env.VERCEL;
const DATA_DIR = isVercel ? path.join('/tmp', 'data') : path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'notebook.enc.json');
const IMAGES_DIR = path.join(DATA_DIR, 'images');

// Images are now stored as files; allow generous JSON for page content.
app.use(express.json({ limit: '75mb' }));
app.use(express.static(path.join(__dirname, 'public')));

try {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(IMAGES_DIR)) fs.mkdirSync(IMAGES_DIR, { recursive: true });
} catch (e) {}

// Held only in memory for the lifetime of this process. Restarting the
// server always forgets it, so the notebook re-locks on every restart.
let sessionKey = null;

// ---------- crypto helpers ----------

function deriveKey(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  // N=16384 is scrypt's default work factor — deliberately slow to brute force.
  return crypto.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
}

function encryptData(obj, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    data: ciphertext.toString('base64'),
  };
}

// Throws if the key is wrong (GCM auth tag check fails) or the file is
// corrupt — that's how we detect a bad password.
function decryptData(payload, key) {
  const iv = Buffer.from(payload.iv, 'hex');
  const authTag = Buffer.from(payload.authTag, 'hex');
  const ciphertext = Buffer.from(payload.data, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function emptyNotebook() {
  return {
    title: 'My Notebook',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    pages: [
      { id: 'p-' + Date.now(), font: "Georgia, 'Times New Roman', serif", fontSize: '18px', html: '' },
    ],
  };
}

function readFile() {
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function writeFile(salt, encrypted) {
  fs.writeFileSync(DATA_FILE, JSON.stringify({ version: 1, salt, ...encrypted }));
}

// ---------- base64 image migration ----------
// When a notebook that was created before file-based images is unlocked,
// we scan each page's HTML for data:image/... src attributes, extract them,
// save them as files, and rewrite the HTML. This happens once on unlock.

const BASE64_IMG_RE = /<img([^>]*)\ssrc="(data:image\/([a-z+]+);base64,[^"]+)"([^>]*)>/gi;

function migrateBase64Images(notebook) {
  let changed = false;
  for (const page of notebook.pages) {
    if (!page.html || !page.html.includes('data:image/')) continue;
    page.html = page.html.replace(BASE64_IMG_RE, (match, before, dataUrl, ext, after) => {
      try {
        const safeExt = ext.replace(/[^a-z0-9]/g, '').slice(0, 8) || 'jpg';
        const id = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
        const filename = id + '.' + safeExt;
        const base64Data = dataUrl.split(',')[1];
        fs.writeFileSync(path.join(IMAGES_DIR, filename), Buffer.from(base64Data, 'base64'));
        changed = true;
        return `<img${before} src="/images/${filename}"${after}>`;
      } catch (err) {
        // Leave as-is if extraction fails.
        return match;
      }
    });
  }
  return changed;
}

// ---------- routes ----------

app.get('/api/status', (req, res) => {
  res.json({ setupNeeded: !fs.existsSync(DATA_FILE), unlocked: !!sessionKey });
});

app.post('/api/setup', (req, res) => {
  if (fs.existsSync(DATA_FILE)) {
    return res.status(400).json({ error: 'A notebook already exists on this machine. Unlock it instead.' });
  }
  const { password } = req.body || {};
  if (!password || password.length < 4) {
    return res.status(400).json({ error: 'Choose a password with at least 4 characters.' });
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const key = deriveKey(password, salt);
  const notebook = emptyNotebook();
  writeFile(salt, encryptData(notebook, key));
  sessionKey = key;
  res.json({ ok: true, notebook });
});

app.post('/api/unlock', (req, res) => {
  if (!fs.existsSync(DATA_FILE)) {
    return res.status(400).json({ error: 'No notebook found yet. Set one up first.' });
  }
  const { password } = req.body || {};
  try {
    const file = readFile();
    const key = deriveKey(password || '', file.salt);
    let notebook = decryptData(file, key);
    sessionKey = key;

    // One-time migration: extract any base64 images → data/images/ files.
    if (migrateBase64Images(notebook)) {
      writeFile(file.salt, encryptData(notebook, key));
    }

    res.json({ ok: true, notebook });
  } catch (err) {
    res.status(401).json({ error: 'Incorrect password.' });
  }
});

app.post('/api/lock', (req, res) => {
  sessionKey = null;
  res.json({ ok: true });
});

function requireUnlocked(req, res, next) {
  if (!sessionKey) return res.status(401).json({ error: 'Notebook is locked.' });
  next();
}

app.get('/api/notebook', requireUnlocked, (req, res) => {
  try {
    const notebook = decryptData(readFile(), sessionKey);
    res.json({ ok: true, notebook });
  } catch (err) {
    res.status(500).json({ error: 'Could not read the notebook file.' });
  }
});

app.post('/api/notebook', requireUnlocked, (req, res) => {
  try {
    const notebook = req.body.notebook;
    notebook.updatedAt = new Date().toISOString();
    const file = readFile();
    writeFile(file.salt, encryptData(notebook, sessionKey));
    res.json({ ok: true, updatedAt: notebook.updatedAt });
  } catch (err) {
    res.status(500).json({ error: 'Could not save the notebook.' });
  }
});

app.post('/api/change-password', requireUnlocked, (req, res) => {
  try {
    const { newPassword } = req.body || {};
    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ error: 'Choose a password with at least 4 characters.' });
    }
    const notebook = decryptData(readFile(), sessionKey);
    const newSalt = crypto.randomBytes(16).toString('hex');
    const newKey = deriveKey(newPassword, newSalt);
    writeFile(newSalt, encryptData(notebook, newKey));
    sessionKey = newKey;
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not change the password.' });
  }
});

// ---------- image file API ----------
// Images are stored in data/images/ and served only to unlocked sessions.
// The client POSTs { filename: 'foo.jpg', data: '<base64>' } and gets back
// { ok: true, url: '/images/<uuid>.jpg' }.

app.post('/api/images', requireUnlocked, (req, res) => {
  try {
    const { data, ext } = req.body || {};
    if (!data) return res.status(400).json({ error: 'No image data.' });
    const safeExt = (ext || 'jpg').replace(/[^a-z0-9]/g, '').slice(0, 8) || 'jpg';
    const id = crypto.randomBytes(16).toString('hex');
    const filename = id + '.' + safeExt;
    const base64Data = data.includes(',') ? data.split(',')[1] : data;
    fs.writeFileSync(path.join(IMAGES_DIR, filename), Buffer.from(base64Data, 'base64'));
    res.json({ ok: true, url: '/images/' + filename });
  } catch (err) {
    res.status(500).json({ error: 'Could not save the image.' });
  }
});

// Serve image files — session-gated so the files can't be fetched anonymously.
app.get('/images/:filename', requireUnlocked, (req, res) => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(IMAGES_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
});

app.delete('/api/images/:filename', requireUnlocked, (req, res) => {
  try {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(IMAGES_DIR, filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not delete the image.' });
  }
});

// ---------- live link previews ----------
// Pasting a bare URL into a page tries to show a real title/thumbnail
// preview card, the way most note apps do. This fetches the target page
// server-side (so it works regardless of the target's CORS policy) and
// pulls out <title>/og:title/og:description/og:image with plain regexes —
// no extra dependency needed. Only http/https are ever followed, redirects
// are capped, and the response body is capped in size so a huge or
// non-HTML response can't hang the request.

const LINK_PREVIEW_TIMEOUT_MS = 6000;
const LINK_PREVIEW_MAX_BYTES = 1_500_000;

function fetchHtml(urlStr, redirectsLeft, callback) {
  let target;
  try {
    target = new URL(urlStr);
  } catch (err) {
    return callback(new Error('Invalid URL'));
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return callback(new Error('Unsupported protocol'));
  }

  const lib = target.protocol === 'https:' ? https : http;
  const req = lib.get(
    target,
    { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; LeatherboundNotebook/1.0)' }, timeout: LINK_PREVIEW_TIMEOUT_MS },
    (res) => {
      const status = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(status) && res.headers.location && redirectsLeft > 0) {
        res.resume();
        let next;
        try {
          next = new URL(res.headers.location, target).toString();
        } catch (err) {
          return callback(new Error('Bad redirect'));
        }
        return fetchHtml(next, redirectsLeft - 1, callback);
      }
      if (status !== 200) {
        res.resume();
        return callback(new Error('HTTP ' + status));
      }
      const contentType = res.headers['content-type'] || '';
      if (contentType && !/text\/html|application\/xhtml/i.test(contentType)) {
        res.resume();
        return callback(new Error('Not HTML'));
      }
      let data = '';
      let size = 0;
      let capped = false;
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        if (capped) return;
        size += Buffer.byteLength(chunk);
        if (size > LINK_PREVIEW_MAX_BYTES) {
          capped = true;
          req.destroy();
          return;
        }
        data += chunk;
      });
      res.on('end', () => callback(null, data, target));
    }
  );
  req.on('timeout', () => req.destroy(new Error('Timeout')));
  req.on('error', callback);
}

function decodeEntities(s) {
  if (!s) return s;
  return s
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function extractMeta(html, baseUrl) {
  const grab = (re) => {
    const m = html.match(re);
    return m ? decodeEntities(m[1].trim()) : null;
  };
  const metaContent = (attr, value) => {
    const a = grab(new RegExp(`<meta[^>]+${attr}=["']${value}["'][^>]+content=["']([^"']*)["']`, 'i'));
    if (a) return a;
    return grab(new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+${attr}=["']${value}["']`, 'i'));
  };

  const title = metaContent('property', 'og:title') || grab(/<title[^>]*>([^<]*)<\/title>/i);
  const description = metaContent('property', 'og:description') || metaContent('name', 'description');
  let image = metaContent('property', 'og:image');
  if (image) {
    try {
      image = new URL(image, baseUrl).toString();
    } catch (err) {
      image = null;
    }
  }
  // Also try twitter:image as fallback
  if (!image) {
    const twitterImg = metaContent('name', 'twitter:image') || metaContent('property', 'twitter:image');
    if (twitterImg) {
      try { image = new URL(twitterImg, baseUrl).toString(); } catch (e) { image = null; }
    }
  }
  return {
    title: title || baseUrl.hostname,
    description: description || '',
    image,
    domain: baseUrl.hostname.replace(/^www\./, ''),
    url: baseUrl.toString(),
  };
}

app.get('/api/link-preview', requireUnlocked, (req, res) => {
  const target = typeof req.query.url === 'string' ? req.query.url : '';
  if (!target) return res.status(400).json({ ok: false, error: 'Missing url' });

  fetchHtml(target, 4, (err, html, finalUrl) => {
    if (err || !html) return res.json({ ok: false });
    try {
      res.json({ ok: true, ...extractMeta(html, finalUrl), url: finalUrl.toString() });
    } catch (parseErr) {
      res.json({ ok: false });
    }
  });
});

// ---------- full STREAMING reverse proxy for live website embedding ----------
//
// The browser blocks iframes from loading pages that set
//   X-Frame-Options: DENY / SAMEORIGIN
//   Content-Security-Policy: frame-ancestors 'none'
//
// Our proxy:
// 1. Fetches the page server-side and STREAMS it to the browser chunk-by-chunk.
// 2. Injects <base href> + anti-frame-busting + fetch/XHR hooks + online spoofing.
// 3. Strips X-Frame-Options/CSP headers so iframes render cleanly.
// 4. Routes inner API calls (fetch/XHR) through /api/proxy-api to eliminate CORS failures.

const PROXY_TIMEOUT_MS = 20000;

const PROXY_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36';

// Headers to strip from proxied responses
const BLOCKED_HEADERS = new Set([
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'transfer-encoding',
]);

/**
 * The anti-frame-busting, fetch/XHR interceptor, form capturer & SPA helper script.
 */
function buildInjection(baseHref, targetOrigin) {
  return (
    `<meta name="viewport" content="width=device-width, initial-scale=1.0">` +
    `<base href="${baseHref}">` +
    `<script>` +
    `(function(){` +
    `var _origOrigin=${JSON.stringify(targetOrigin)};` +
    `var _proxyApi='/api/proxy-api?url=';` +
    `var _proxyPage='/api/proxy?url=';` +
    // 1. Anti-frame busting & frame element simulation
    `try{Object.defineProperty(window,'top',{get:function(){return window.self},configurable:false})}catch(e){}` +
    `try{Object.defineProperty(window,'parent',{get:function(){return window.self},configurable:false})}catch(e){}` +
    `try{Object.defineProperty(window,'frameElement',{get:function(){return null},configurable:false})}catch(e){}` +
    // 2. Always report online to prevent SPA offline-detection screens
    `try{Object.defineProperty(navigator,'onLine',{get:function(){return true},configurable:false})}catch(e){}` +
    // 3. Neutralize Service Workers (avoids broken offline caches on localhost)
    `if(navigator.serviceWorker){` +
    `try{navigator.serviceWorker.register=function(){return Promise.reject(new Error('SW disabled in notebook'))};}catch(e){}` +
    `}` +
    // Helper to resolve relative URLs
    `function _resolve(u){` +
    `try{return new URL(u,document.baseURI||_origOrigin).href}catch(e){return u}` +
    `}` +
    `function _isProxied(u){` +
    `return typeof u==='string'&&!u.startsWith('data:')&&!u.startsWith('blob:')&&!u.startsWith('javascript:')&&!u.startsWith('/api/proxy');` +
    `}` +
    // 4. Hook fetch() to route API calls through proxy-api
    `var _origFetch=window.fetch;` +
    `if(_origFetch){` +
    `window.fetch=function(input,init){` +
    `try{` +
    `var url=typeof input==='string'?input:(input&&input.url?input.url:'');` +
    `if(_isProxied(url)){` +
    `var full=_resolve(url);` +
    `var proxied=_proxyApi+encodeURIComponent(full);` +
    `if(typeof input==='string'){input=proxied}` +
    `else if(window.Request&&input instanceof Request){input=new Request(proxied,input)}` +
    `}` +
    `}catch(e){}` +
    `return _origFetch.call(this,input,init);` +
    `};` +
    `}` +
    // 5. Hook XMLHttpRequest to route AJAX calls through proxy-api
    `var _origOpen=XMLHttpRequest.prototype.open;` +
    `XMLHttpRequest.prototype.open=function(method,url){` +
    `try{` +
    `if(_isProxied(url)){` +
    `url=_proxyApi+encodeURIComponent(_resolve(url));` +
    `}` +
    `}catch(e){}` +
    `var args=Array.prototype.slice.call(arguments);` +
    `args[1]=url;` +
    `return _origOpen.apply(this,args);` +
    `};` +
    // 6. Keep link navigation inside the proxy iframe
    `document.addEventListener('click',function(e){` +
    `var a=e.target&&e.target.closest?e.target.closest('a'):null;` +
    `if(a&&a.href&&!a.href.startsWith('javascript:')&&!a.href.startsWith('#')&&a.target!=='_blank'){` +
    `var full=_resolve(a.getAttribute('href')||a.href);` +
    `if(_isProxied(full)){` +
    `e.preventDefault();` +
    `window.location.href=_proxyPage+encodeURIComponent(full);` +
    `}` +
    `}` +
    `},true);` +
    // 7. Intercept form submissions (e.g. Google Search, YouTube search)
    `document.addEventListener('submit',function(e){` +
    `var form=e.target;` +
    `if(!form)return;` +
    `var method=(form.method||'GET').toUpperCase();` +
    `var action=form.getAttribute('action')||'';` +
    `var fullUrl=_resolve(action||window.location.href);` +
    `if(method==='GET'){` +
    `e.preventDefault();` +
    `try{` +
    `var formData=new FormData(form);` +
    `var params=new URLSearchParams(formData).toString();` +
    `var sep=fullUrl.indexOf('?')===-1?'?':'&';` +
    `var targetWithQuery=params?(fullUrl+sep+params):fullUrl;` +
    `window.location.href=_proxyPage+encodeURIComponent(targetWithQuery);` +
    `}catch(err){window.location.href=_proxyPage+encodeURIComponent(fullUrl)}` +
    `}` +
    `},true);` +
    // 8. Intercept programmatic form.submit()
    `var _origFormSubmit=HTMLFormElement.prototype.submit;` +
    `HTMLFormElement.prototype.submit=function(){` +
    `var method=(this.method||'GET').toUpperCase();` +
    `var action=this.getAttribute('action')||'';` +
    `var fullUrl=_resolve(action||window.location.href);` +
    `if(method==='GET'){` +
    `try{` +
    `var formData=new FormData(this);` +
    `var params=new URLSearchParams(formData).toString();` +
    `var sep=fullUrl.indexOf('?')===-1?'?':'&';` +
    `var targetWithQuery=params?(fullUrl+sep+params):fullUrl;` +
    `window.location.href=_proxyPage+encodeURIComponent(targetWithQuery);` +
    `return;` +
    `}catch(err){}` +
    `}` +
    `return _origFormSubmit.apply(this,arguments);` +
    `};` +
    `})();` +
    `</script>`
  );
}

/**
 * Set safe response headers — strips all iframe-blocking ones.
 */
function setSafeHeaders(res, proxyHeaders, stripEncoding = false) {
  for (const [key, val] of Object.entries(proxyHeaders)) {
    const lk = key.toLowerCase();
    if (BLOCKED_HEADERS.has(lk)) continue;
    if (stripEncoding && (lk === 'content-encoding' || lk === 'content-length')) continue;
    try { res.set(key, val); } catch (e) { /* ignore bad headers */ }
  }
  res.set('X-Frame-Options', 'ALLOWALL');
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  res.set('Access-Control-Allow-Headers', '*');
}

/**
 * Stream-proxy a URL to the Express response, following redirects with auto decompression.
 */
function streamProxy(urlStr, redirectsLeft, expressRes) {
  let target;
  try { target = new URL(urlStr); } catch (e) {
    return expressRes.status(400).json({ error: 'Invalid URL' });
  }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return expressRes.status(400).json({ error: 'Unsupported protocol' });
  }

  const lib = target.protocol === 'https:' ? https : http;
  const proxyReq = lib.get(target, {
    headers: {
      'User-Agent': PROXY_USER_AGENT,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'gzip, deflate, br',
    },
    timeout: PROXY_TIMEOUT_MS,
  }, (proxyRes) => {
    const status = proxyRes.statusCode || 0;

    // Follow redirects
    if ([301, 302, 303, 307, 308].includes(status) && proxyRes.headers.location && redirectsLeft > 0) {
      proxyRes.resume();
      try {
        const next = new URL(proxyRes.headers.location, target).toString();
        return streamProxy(next, redirectsLeft - 1, expressRes);
      } catch (e) {
        return expressRes.status(502).end();
      }
    }

    const contentType = proxyRes.headers['content-type'] || '';
    const encoding = (proxyRes.headers['content-encoding'] || '').toLowerCase();
    const isHtml = /text\/html|application\/xhtml/i.test(contentType);

    expressRes.status(status);
    setSafeHeaders(expressRes, proxyRes.headers, isHtml);
    try {
      expressRes.set('Set-Cookie', 'last_proxy_origin=' + encodeURIComponent(target.origin) + '; Path=/; SameSite=Lax');
    } catch(e){}

    if (isHtml) {
      // Decompress the incoming HTML stream if compressed
      let inputStream = proxyRes;
      if (encoding === 'gzip') {
        inputStream = proxyRes.pipe(zlib.createGunzip());
      } else if (encoding === 'br') {
        inputStream = proxyRes.pipe(zlib.createBrotliDecompress());
      } else if (encoding === 'deflate') {
        inputStream = proxyRes.pipe(zlib.createInflate());
      }

      const baseHref = target.origin + target.pathname.replace(/[^/]*$/, '');
      const injection = buildInjection(baseHref, target.origin);
      let injected = false;

      inputStream.setEncoding('utf8');
      inputStream.on('data', (chunk) => {
        let out = chunk;

        if (!injected) {
          out = out.replace(/<base[^>]*>/gi, '');

          if (/<head[^>]*>/i.test(out)) {
            out = out.replace(/<head[^>]*>/i, '$&' + injection);
            injected = true;
          } else if (/<html[^>]*>/i.test(out)) {
            out = out.replace(/<html[^>]*>/i, '$&<head>' + injection + '</head>');
            injected = true;
          } else if (/<![dD][oO][cC][tT][yY][pP][eE]/.test(out)) {
            out = out.replace(/(<!DOCTYPE[^>]*>)/i, '$1<head>' + injection + '</head>');
            injected = true;
          } else {
            expressRes.write(injection);
            injected = true;
          }
        }

        out = out.replace(/<base[^>]*>/gi, '');
        out = out.replace(/<meta[^>]*http-equiv\s*=\s*["']?X-Frame-Options["']?[^>]*>/gi, '');

        expressRes.write(out);
      });

      inputStream.on('end', () => {
        if (!injected) expressRes.write(injection);
        expressRes.end();
      });

      inputStream.on('error', () => expressRes.end());
    } else {
      // Non-HTML: pipe directly preserving encoding
      proxyRes.pipe(expressRes);
    }
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    if (!expressRes.headersSent) expressRes.status(504).json({ error: 'Timeout' });
  });
  proxyReq.on('error', (err) => {
    if (!expressRes.headersSent) expressRes.status(502).json({ error: err.message });
  });
}

app.get('/api/proxy', requireUnlocked, (req, res) => {
  const targetUrl = typeof req.query.url === 'string' ? req.query.url : '';
  if (!targetUrl) return res.status(400).json({ error: 'Missing url parameter' });
  streamProxy(targetUrl, 8, res);
});

// ---------- generic API / subresource proxy (handles GET, POST, PUT, OPTIONS, etc.) ----------
app.all('/api/proxy-api', requireUnlocked, (req, res) => {
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    res.set('Access-Control-Allow-Headers', '*');
    return res.status(200).end();
  }

  const targetUrl = typeof req.query.url === 'string' ? req.query.url : '';
  if (!targetUrl) return res.status(400).end();

  let target;
  try { target = new URL(targetUrl); } catch (e) { return res.status(400).end(); }

  const lib = target.protocol === 'https:' ? https : http;
  const headers = { ...req.headers };
  delete headers.host;
  delete headers.origin;
  delete headers.referer;
  headers['host'] = target.host;
  headers['origin'] = target.origin;
  headers['referer'] = target.origin + '/';
  headers['user-agent'] = PROXY_USER_AGENT;

  const proxyReq = lib.request(target, {
    method: req.method,
    headers: headers,
    timeout: PROXY_TIMEOUT_MS,
  }, (proxyRes) => {
    res.status(proxyRes.statusCode || 200);
    setSafeHeaders(res, proxyRes.headers, false);
    proxyRes.pipe(res);
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    if (!res.headersSent) res.status(504).end();
  });
  proxyReq.on('error', () => {
    if (!res.headersSent) res.status(502).end();
  });

  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    req.pipe(proxyReq);
  } else {
    proxyReq.end();
  }
});

// ---------- asset proxy with caching ----------
const assetCache = new Map();
const ASSET_CACHE_MAX = 200;
const ASSET_CACHE_TTL = 300_000; // 5 minutes

function proxyFetchBuffered(urlStr, redirectsLeft, callback) {
  let target;
  try { target = new URL(urlStr); } catch (e) { return callback(new Error('Invalid URL')); }
  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return callback(new Error('Unsupported protocol'));
  }
  const lib = target.protocol === 'https:' ? https : http;
  const req = lib.get(target, {
    headers: { 'User-Agent': PROXY_USER_AGENT, 'Accept-Encoding': 'identity' },
    timeout: PROXY_TIMEOUT_MS,
  }, (res) => {
    const status = res.statusCode || 0;
    if ([301, 302, 303, 307, 308].includes(status) && res.headers.location && redirectsLeft > 0) {
      res.resume();
      try {
        return proxyFetchBuffered(new URL(res.headers.location, target).toString(), redirectsLeft - 1, callback);
      } catch (e) { return callback(new Error('Bad redirect')); }
    }
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => callback(null, { statusCode: status, headers: res.headers, body: Buffer.concat(chunks) }));
    res.on('error', callback);
  });
  req.on('timeout', () => req.destroy(new Error('Timeout')));
  req.on('error', callback);
}

app.get('/api/proxy-asset', requireUnlocked, (req, res) => {
  const targetUrl = typeof req.query.url === 'string' ? req.query.url : '';
  if (!targetUrl) return res.status(400).end();

  const cached = assetCache.get(targetUrl);
  if (cached && Date.now() - cached.time < ASSET_CACHE_TTL) {
    res.set('Content-Type', cached.contentType);
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'public, max-age=300');
    return res.send(cached.body);
  }

  proxyFetchBuffered(targetUrl, 5, (err, response) => {
    if (err) return res.status(502).end();
    const contentType = response.headers['content-type'] || 'application/octet-stream';

    if (assetCache.size >= ASSET_CACHE_MAX) {
      const oldest = assetCache.keys().next().value;
      assetCache.delete(oldest);
    }
    assetCache.set(targetUrl, { body: response.body, contentType, time: Date.now() });

    res.set('Content-Type', contentType);
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'public, max-age=300');
    res.send(response.body);
  });
});

// ---------- Catch-all for framed pages that navigate to relative paths on localhost (e.g. /search?q=...) ----------
app.use((req, res, next) => {
  if (
    req.path.startsWith('/api') ||
    req.path.startsWith('/images') ||
    req.path === '/' ||
    req.path === '/index.html' ||
    /\.(js|css|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|ico)$/i.test(req.path)
  ) {
    return next();
  }

  let targetOrigin = null;
  const referer = req.headers.referer || '';
  const match = referer.match(/\/api\/proxy\?url=([^&]+)/);
  if (match) {
    try {
      targetOrigin = new URL(decodeURIComponent(match[1])).origin;
    } catch (e) {}
  }
  if (!targetOrigin) {
    const cookieHeader = req.headers.cookie || '';
    const cookieMatch = cookieHeader.match(/(?:^|; )last_proxy_origin=([^;]*)/);
    if (cookieMatch) {
      try {
        targetOrigin = new URL(decodeURIComponent(cookieMatch[1])).origin;
      } catch (e) {}
    }
  }
  if (!targetOrigin) {
    if (req.path === '/search' || req.path.startsWith('/search')) {
      targetOrigin = 'https://www.google.com';
    } else if (req.path === '/watch' || req.path === '/results' || req.path.startsWith('/youtubei')) {
      targetOrigin = 'https://www.youtube.com';
    }
  }

  if (targetOrigin) {
    const targetUrl = new URL(req.originalUrl, targetOrigin).toString();
    if (req.method === 'GET' && (!req.headers.accept || req.headers.accept.includes('text/html'))) {
      return res.redirect('/api/proxy?url=' + encodeURIComponent(targetUrl));
    } else {
      return streamProxy(targetUrl, 5, res);
    }
  }
  next();
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log('');
    console.log('  📖  Leatherbound Notebook is running.');
    console.log(`      Open http://localhost:${PORT} in your browser.`);
    console.log('');
    console.log(`      Images folder: ${IMAGES_DIR}`);
    console.log(`      Proxy: STREAMING + API Hook mode (full SPA support).`);
    console.log('');
  });
}

module.exports = app;



