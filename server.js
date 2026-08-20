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
const os = require('os');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;
const isVercel = !!process.env.VERCEL;

function resolveDataDir() {
  if (isVercel) {
    return path.join('/tmp', 'data');
  }
  const defaultDir = path.join(__dirname, 'data');
  try {
    if (!fs.existsSync(defaultDir)) {
      fs.mkdirSync(defaultDir, { recursive: true });
    }
    const testFile = path.join(defaultDir, '.write_test_' + process.pid);
    fs.writeFileSync(testFile, '1');
    fs.unlinkSync(testFile);
    return defaultDir;
  } catch (err) {
    return path.join(os.tmpdir ? os.tmpdir() : '/tmp', 'data');
  }
}

const DATA_DIR = resolveDataDir();
const DATA_FILE = path.join(DATA_DIR, 'notebook.enc.json');
const IMAGES_DIR = path.join(DATA_DIR, 'images');

// Images are now stored as files; allow generous JSON for page content.
app.use(express.json({ limit: '75mb' }));
app.use(express.static(path.join(__dirname, 'public')));

try {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(IMAGES_DIR)) fs.mkdirSync(IMAGES_DIR, { recursive: true });
  const bundledDir = path.join(__dirname, 'data');
  if (DATA_DIR !== bundledDir && fs.existsSync(bundledDir)) {
    const bundledFile = path.join(bundledDir, 'notebook.enc.json');
    if (!fs.existsSync(DATA_FILE) && fs.existsSync(bundledFile)) {
      fs.copyFileSync(bundledFile, DATA_FILE);
    }
    const bundledImages = path.join(bundledDir, 'images');
    if (fs.existsSync(bundledImages) && fs.existsSync(IMAGES_DIR)) {
      try {
        const files = fs.readdirSync(bundledImages);
        for (const file of files) {
          const dest = path.join(IMAGES_DIR, file);
          if (!fs.existsSync(dest)) {
            fs.copyFileSync(path.join(bundledImages, file), dest);
          }
        }
      } catch (e) {}
    }
  }
} catch (e) {}

// Held in memory for the lifetime of this process.
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

// ---------- Session Token Helper for Serverless Persistence ----------
const SESSION_SECRET = crypto.createHash('sha256').update(process.env.SESSION_SECRET || 'leatherbound-master-session-salt-v3').digest();

function encryptSessionToken(key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_SECRET, iv);
  const encrypted = Buffer.concat([cipher.update(key), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + '.' + authTag.toString('hex') + '.' + encrypted.toString('hex');
}

function decryptSessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = Buffer.from(parts[2], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', SESSION_SECRET, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (e) {
    return null;
  }
}

function setSessionCookie(res, token, req) {
  const cookieVal = encodeURIComponent(token);
  const isHttps = isVercel || (req && (req.secure || (req.headers && req.headers['x-forwarded-proto'] === 'https')));
  const flags = isHttps
    ? 'Path=/; HttpOnly; SameSite=None; Secure; Max-Age=2592000'
    : 'Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000';
  res.set('Set-Cookie', `notebook_session=${cookieVal}; ${flags}`);
}

function getSessionKey(req) {
  const cookieHeader = (req && req.headers && req.headers.cookie) || '';
  const match = cookieHeader.match(/(?:^|; )notebook_session=([^;]*)/);
  if (match) {
    const key = decryptSessionToken(decodeURIComponent(match[1]));
    if (key) {
      sessionKey = key;
      return key;
    }
  }
  return null;
}

// ---------- Multi-Book Vault Structure & Normalization ----------

function emptyVault() {
  const initialBook = {
    id: 'book-' + Date.now(),
    title: 'My Notebook',
    coverColor: 'brown',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    pages: [
      { id: 'p-' + Date.now(), font: "Georgia, 'Times New Roman', serif", fontSize: '18px', html: '' },
    ],
  };
  return {
    version: 2,
    activeBookId: initialBook.id,
    books: [initialBook],
  };
}

function normalizeVault(data) {
  if (data && Array.isArray(data.books) && data.books.length > 0) {
    if (!data.activeBookId || !data.books.some((b) => b.id === data.activeBookId)) {
      data.activeBookId = data.books[0].id;
    }
    return data;
  }
  const defaultBook = {
    id: 'book-default',
    title: (data && data.title) || 'My Notebook',
    coverColor: (data && data.coverColor) || 'brown',
    createdAt: (data && data.createdAt) || new Date().toISOString(),
    updatedAt: (data && data.updatedAt) || new Date().toISOString(),
    pages: (data && data.pages) || [
      { id: 'p-' + Date.now(), font: "Georgia, 'Times New Roman', serif", fontSize: '18px', html: '' },
    ],
  };
  return {
    version: 2,
    activeBookId: defaultBook.id,
    books: [defaultBook],
  };
}

function getActiveBook(vault) {
  return vault.books.find((b) => b.id === vault.activeBookId) || vault.books[0];
}

function readFile() {
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function writeFile(salt, encrypted) {
  fs.writeFileSync(DATA_FILE, JSON.stringify({ version: 2, salt, ...encrypted }));
}

// ---------- base64 image migration ----------
const BASE64_IMG_RE = /<img([^>]*)\ssrc="(data:image\/([a-z+]+);base64,[^"]+)"([^>]*)>/gi;

function migrateBase64Images(vault) {
  let changed = false;
  if (!vault || !vault.books) return false;
  for (const book of vault.books) {
    if (!book.pages) continue;
    for (const page of book.pages) {
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
          return match;
        }
      });
    }
  }
  return changed;
}

// ---------- routes ----------

function requireUnlocked(req, res, next) {
  const key = getSessionKey(req);
  if (!key) return res.status(401).json({ error: 'Notebook is locked.' });
  req.sessionKey = key;
  next();
}

app.get('/api/status', (req, res) => {
  const key = getSessionKey(req);
  res.json({ setupNeeded: !fs.existsSync(DATA_FILE), unlocked: !!key });
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
  const vault = emptyVault();
  writeFile(salt, encryptData(vault, key));
  sessionKey = key;

  const token = encryptSessionToken(key);
  setSessionCookie(res, token, req);
  res.json({ ok: true, vault, activeBookId: vault.activeBookId, notebook: getActiveBook(vault) });
});

app.post('/api/unlock', (req, res) => {
  if (!fs.existsSync(DATA_FILE)) {
    return res.status(400).json({ error: 'No notebook found yet. Set one up first.' });
  }
  const { password } = req.body || {};
  try {
    const file = readFile();
    const key = deriveKey(password || '', file.salt);
    let raw = decryptData(file, key);
    let vault = normalizeVault(raw);
    sessionKey = key;

    // One-time migration: extract any base64 images → data/images/ files.
    if (migrateBase64Images(vault)) {
      writeFile(file.salt, encryptData(vault, key));
    }

    const token = encryptSessionToken(key);
    setSessionCookie(res, token, req);
    res.json({ ok: true, vault, activeBookId: vault.activeBookId, notebook: getActiveBook(vault) });
  } catch (err) {
    res.status(401).json({ error: 'Incorrect password.' });
  }
});

app.post('/api/lock', (req, res) => {
  sessionKey = null;
  res.set('Set-Cookie', `notebook_session=; Path=/; HttpOnly; Max-Age=0`);
  res.json({ ok: true });
});

app.get('/api/notebook', requireUnlocked, (req, res) => {
  try {
    const raw = decryptData(readFile(), req.sessionKey);
    const vault = normalizeVault(raw);
    res.json({ ok: true, vault, activeBookId: vault.activeBookId, notebook: getActiveBook(vault) });
  } catch (err) {
    res.status(500).json({ error: 'Could not read the notebook file.' });
  }
});

function handleSaveNotebook(req, res) {
  try {
    const raw = decryptData(readFile(), req.sessionKey);
    let vault = normalizeVault(raw);

    if (req.body.vault) {
      vault = normalizeVault(req.body.vault);
    } else if (req.body.notebook) {
      const updated = req.body.notebook;
      updated.updatedAt = new Date().toISOString();
      const idx = vault.books.findIndex((b) => b.id === (updated.id || vault.activeBookId));
      if (idx !== -1) {
        vault.books[idx] = updated;
      } else {
        vault.books.push(updated);
      }
    }

    const file = readFile();
    writeFile(file.salt, encryptData(vault, req.sessionKey));
    const active = getActiveBook(vault);
    res.json({ ok: true, updatedAt: active.updatedAt, vault, notebook: active });
  } catch (err) {
    res.status(500).json({ error: 'Could not save the notebook.' });
  }
}

app.post('/api/notebook', requireUnlocked, handleSaveNotebook);
app.post('/api/save', requireUnlocked, handleSaveNotebook);

// ---------- Multiple Books Management Routes ----------

app.get('/api/books', requireUnlocked, (req, res) => {
  try {
    const raw = decryptData(readFile(), req.sessionKey);
    const vault = normalizeVault(raw);
    const summary = vault.books.map((b) => ({
      id: b.id,
      title: b.title,
      coverColor: b.coverColor || 'brown',
      pageCount: (b.pages || []).length,
      updatedAt: b.updatedAt,
    }));
    res.json({ ok: true, activeBookId: vault.activeBookId, books: summary });
  } catch (err) {
    res.status(500).json({ error: 'Could not fetch books list.' });
  }
});

app.post('/api/books/create', requireUnlocked, (req, res) => {
  try {
    const { title, coverColor } = req.body || {};
    const raw = decryptData(readFile(), req.sessionKey);
    const vault = normalizeVault(raw);

    const newBook = {
      id: 'book-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex'),
      title: (title || 'New Notebook').trim().slice(0, 80) || 'New Notebook',
      coverColor: coverColor || 'brown',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      pages: [
        { id: 'p-' + Date.now(), font: "Georgia, 'Times New Roman', serif", fontSize: '18px', html: '' },
      ],
    };

    vault.books.push(newBook);
    vault.activeBookId = newBook.id;

    const file = readFile();
    writeFile(file.salt, encryptData(vault, req.sessionKey));
    res.json({ ok: true, vault, activeBookId: newBook.id, notebook: newBook });
  } catch (err) {
    res.status(500).json({ error: 'Could not create book.' });
  }
});

app.post('/api/books/switch', requireUnlocked, (req, res) => {
  try {
    const { bookId } = req.body || {};
    const raw = decryptData(readFile(), req.sessionKey);
    const vault = normalizeVault(raw);

    if (!vault.books.some((b) => b.id === bookId)) {
      return res.status(404).json({ error: 'Book not found.' });
    }

    vault.activeBookId = bookId;
    const file = readFile();
    writeFile(file.salt, encryptData(vault, req.sessionKey));
    res.json({ ok: true, vault, activeBookId: bookId, notebook: getActiveBook(vault) });
  } catch (err) {
    res.status(500).json({ error: 'Could not switch book.' });
  }
});

function handleDeleteBook(req, res) {
  try {
    const bookId = (req.body && req.body.bookId) || req.params.id;
    if (!bookId) return res.status(400).json({ error: 'Missing bookId' });
    const raw = decryptData(readFile(), req.sessionKey);
    const vault = normalizeVault(raw);

    if (vault.books.length <= 1) {
      return res.status(400).json({ error: 'You must have at least one notebook.' });
    }

    if (!vault.books.some((b) => b.id === bookId)) {
      return res.status(404).json({ error: 'Book not found.' });
    }

    vault.books = vault.books.filter((b) => b.id !== bookId);
    if (vault.activeBookId === bookId) {
      vault.activeBookId = vault.books[0].id;
    }

    const file = readFile();
    writeFile(file.salt, encryptData(vault, req.sessionKey));
    res.json({ ok: true, vault, activeBookId: vault.activeBookId, notebook: getActiveBook(vault) });
  } catch (err) {
    res.status(500).json({ error: 'Could not delete book.' });
  }
}

app.post('/api/books/delete', requireUnlocked, handleDeleteBook);
app.delete('/api/books/:id', requireUnlocked, handleDeleteBook);

function handleRenameBook(req, res) {
  try {
    const bookId = (req.body && req.body.bookId) || req.params.id;
    const { title, coverColor } = req.body || {};
    const raw = decryptData(readFile(), req.sessionKey);
    const vault = normalizeVault(raw);

    const target = vault.books.find((b) => b.id === bookId);
    if (!target) return res.status(404).json({ error: 'Book not found.' });

    if (title !== undefined) target.title = String(title).trim().slice(0, 80);
    if (coverColor !== undefined) target.coverColor = coverColor;
    target.updatedAt = new Date().toISOString();

    const file = readFile();
    writeFile(file.salt, encryptData(vault, req.sessionKey));
    res.json({ ok: true, vault, activeBookId: vault.activeBookId, notebook: getActiveBook(vault) });
  } catch (err) {
    res.status(500).json({ error: 'Could not update book.' });
  }
}

app.post('/api/books/rename', requireUnlocked, handleRenameBook);
app.put('/api/books/:id', requireUnlocked, handleRenameBook);

app.post('/api/change-password', requireUnlocked, (req, res) => {
  try {
    const { newPassword } = req.body || {};
    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ error: 'Choose a password with at least 4 characters.' });
    }
    const vault = normalizeVault(decryptData(readFile(), req.sessionKey));
    const newSalt = crypto.randomBytes(16).toString('hex');
    const newKey = deriveKey(newPassword, newSalt);
    writeFile(newSalt, encryptData(vault, newKey));
    sessionKey = newKey;

    const token = encryptSessionToken(newKey);
    setSessionCookie(res, token, req);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not change the password.' });
  }
});

// ---------- image file API ----------
// Images are stored in data/images/ and served only to unlocked sessions.
// The client POSTs { filename: 'foo.jpg', data: '<base64>' } and gets back
// { ok: true, url: '/images/<uuid>.jpg', filename: '<uuid>.jpg' }.

function handleImageUpload(req, res) {
  try {
    const { data, ext } = req.body || {};
    if (!data) return res.status(400).json({ error: 'No image data.' });
    const safeExt = (ext || 'jpg').replace(/[^a-z0-9]/g, '').slice(0, 8) || 'jpg';
    const id = crypto.randomBytes(16).toString('hex');
    const filename = id + '.' + safeExt;
    const base64Data = data.includes(',') ? data.split(',')[1] : data;
    fs.writeFileSync(path.join(IMAGES_DIR, filename), Buffer.from(base64Data, 'base64'));
    res.json({ ok: true, url: '/images/' + filename, filename });
  } catch (err) {
    res.status(500).json({ error: 'Could not save the image.' });
  }
}

app.post('/api/images', requireUnlocked, handleImageUpload);
app.post('/api/images/upload', requireUnlocked, handleImageUpload);

function handleServeImage(req, res) {
  const raw = req.params.filename;
  if (!raw || typeof raw !== 'string') return res.status(400).end();
  const filename = path.basename(raw);
  if (filename !== raw || filename.includes('..') || !/^[a-zA-Z0-9_.-]+$/.test(filename)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  const safeDir = path.resolve(IMAGES_DIR);
  const filePath = path.resolve(safeDir, filename);
  if (!filePath.startsWith(safeDir + path.sep)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
}

// Serve image files — session-gated so the files can't be fetched anonymously.
app.get('/images/:filename', requireUnlocked, handleServeImage);
app.get('/api/images/:filename', requireUnlocked, handleServeImage);

function handleDeleteImage(req, res) {
  try {
    const raw = req.params.filename;
    if (!raw || typeof raw !== 'string') return res.status(400).end();
    const filename = path.basename(raw);
    if (filename !== raw || filename.includes('..') || !/^[a-zA-Z0-9_.-]+$/.test(filename)) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    const safeDir = path.resolve(IMAGES_DIR);
    const filePath = path.resolve(safeDir, filename);
    if (!filePath.startsWith(safeDir + path.sep)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Could not delete the image.' });
  }
}

app.delete('/api/images/:filename', requireUnlocked, handleDeleteImage);
app.delete('/images/:filename', requireUnlocked, handleDeleteImage);

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

app.get('/api/link-preview', (req, res) => {
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
    `var _hostOrigin=window.location.protocol+'//'+window.location.host;` +
    `var _proxyApi=_hostOrigin+'/api/proxy-api?url=';` +
    `var _proxyPage=_hostOrigin+'/api/proxy?url=';` +
    // 1. Always report online to prevent SPA offline-detection screens
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
    `return typeof u==='string'&&!u.startsWith('data:')&&!u.startsWith('blob:')&&!u.startsWith('javascript:')&&!u.startsWith('/api/proxy')&&!u.startsWith(_proxyApi)&&!u.startsWith(_proxyPage);` +
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
    // 9. Sync title & current URL with notebook embed header
    `function _notifyParent(){` +
    `try{` +
    `if(window.parent&&window.parent!==window){` +
    `window.parent.postMessage({type:'nb-embed-nav',title:document.title||'',url:window.location.href,origin:_origOrigin},'*');` +
    `}` +
    `}catch(e){}` +
    `}` +
    `window.addEventListener('DOMContentLoaded',_notifyParent);` +
    `window.addEventListener('load',_notifyParent);` +
    // 10. Listen for parent commands (back, forward, reload, navigate)
    `window.addEventListener('message',function(e){` +
    `if(!e.data||typeof e.data!=='object')return;` +
    `if(e.data.type==='nb-embed-cmd'){` +
    `if(e.data.action==='back')history.back();` +
    `if(e.data.action==='forward')history.forward();` +
    `if(e.data.action==='reload')window.location.reload();` +
    `if(e.data.action==='nav'&&e.data.url){window.location.href=_proxyPage+encodeURIComponent(e.data.url)}` +
    `}` +
    `});` +
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

    // Follow redirects up to 8 hops
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

    // Handle client disconnect / socket close to prevent resource leaks
    expressRes.on('close', () => {
      if (!proxyRes.complete) {
        try { proxyReq.destroy(); } catch (e) {}
      }
    });

    proxyRes.on('error', (err) => {
      if (!expressRes.headersSent) expressRes.status(502).json({ error: err.message });
      else expressRes.end();
    });

    if (isHtml) {
      // Decompress the incoming HTML stream if compressed
      let inputStream = proxyRes;
      let decompressor = null;
      if (encoding === 'gzip') {
        decompressor = zlib.createGunzip();
      } else if (encoding === 'br') {
        decompressor = zlib.createBrotliDecompress();
      } else if (encoding === 'deflate') {
        decompressor = zlib.createInflate();
      }

      if (decompressor) {
        decompressor.on('error', () => {
          if (!expressRes.headersSent) expressRes.status(502).json({ error: 'Decompression failed' });
          else expressRes.end();
        });
        inputStream = proxyRes.pipe(decompressor);
      }

      const baseHref = target.origin + target.pathname.replace(/[^/]*$/, '');
      const injection = buildInjection(baseHref, target.origin);
      let injected = false;

      inputStream.setEncoding('utf8');
      inputStream.on('data', (chunk) => {
        let out = chunk;

        // Strip existing base and frame-blocking meta tags from incoming chunks first
        out = out.replace(/<base[^>]*>/gi, '');
        out = out.replace(/<meta[^>]*http-equiv\s*=\s*["']?(?:X-Frame-Options|Content-Security-Policy|Content-Security-Policy-Report-Only)["']?[^>]*>/gi, '');

        if (!injected) {
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

        expressRes.write(out);
      });

      inputStream.on('end', () => {
        if (!injected) expressRes.write(injection);
        expressRes.end();
      });

      inputStream.on('error', () => {
        if (!expressRes.headersSent) expressRes.status(502).end();
        else expressRes.end();
      });
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

// ---------- YouTube search scraper API ----------
app.get('/api/youtube-search', (req, res) => {
  const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  if (!query) return res.json({ ok: true, results: [] });

  const url = `https://www.youtube.com/results?search_query=${encodeURIComponent(query)}`;
  https.get(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    timeout: 8000,
  }, (ytRes) => {
    let html = '';
    ytRes.on('data', (c) => { html += c; });
    ytRes.on('end', () => {
      const results = [];
      try {
        const dataMatch = html.match(/var ytInitialData = ({.+?});<\/script>/s) || html.match(/window\["ytInitialData"\] = ({.+?});<\/script>/s);
        if (dataMatch) {
          const data = JSON.parse(dataMatch[1]);
          const contents = data?.contents?.twoColumnSearchResultsRenderer?.primaryContents?.sectionListRenderer?.contents;
          if (Array.isArray(contents)) {
            for (const section of contents) {
              const itemSection = section?.itemSectionRenderer?.contents;
              if (Array.isArray(itemSection)) {
                for (const item of itemSection) {
                  const vr = item.videoRenderer;
                  if (vr && vr.videoId) {
                    results.push({
                      id: vr.videoId,
                      title: vr.title?.runs?.[0]?.text || vr.title?.simpleText || 'YouTube Video',
                      channel: vr.ownerText?.runs?.[0]?.text || '',
                      duration: vr.lengthText?.simpleText || '',
                      thumbnail: vr.thumbnail?.thumbnails?.[0]?.url || `https://i.ytimg.com/vi/${vr.videoId}/hqdefault.jpg`,
                    });
                  }
                }
              }
            }
          }
        }
      } catch (e) {}

      if (results.length === 0) {
        const idMatches = [...html.matchAll(/"videoId":"([a-zA-Z0-9_-]{11})"/g)];
        const seen = new Set();
        for (const m of idMatches) {
          const id = m[1];
          if (!seen.has(id)) {
            seen.add(id);
            results.push({
              id,
              title: `Video (${id})`,
              channel: 'YouTube',
              duration: '',
              thumbnail: `https://i.ytimg.com/vi/${id}/hqdefault.jpg`,
            });
            if (results.length >= 10) break;
          }
        }
      }

      res.json({ ok: true, results: results.slice(0, 12) });
    });
  }).on('error', () => {
    res.json({ ok: true, results: [] });
  });
});

// Built-in interactive YouTube & Web Search Portals
app.get('/api/portal/youtube', (req, res) => {
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.set('X-Frame-Options', 'ALLOWALL');
  res.set('Access-Control-Allow-Origin', '*');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>YouTube Player Portal</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #0f0f0f;
    color: #f1f1f1;
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
  }
  .header {
    background: #212121;
    border-bottom: 1px solid #383838;
    padding: 8px 12px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
  }
  .logo { font-weight: bold; color: #ff0000; font-size: 1.1rem; display: flex; align-items: center; gap: 5px; cursor: pointer; }
  .search-box {
    flex: 1;
    display: flex;
    background: #121212;
    border: 1px solid #303030;
    border-radius: 20px;
    padding: 3px 12px;
  }
  .search-box input {
    flex: 1;
    background: transparent;
    border: none;
    color: #fff;
    font-size: 0.85rem;
    outline: none;
    padding: 4px 6px;
  }
  .search-box button {
    background: none;
    border: none;
    color: #aaa;
    cursor: pointer;
    padding: 0 4px;
    font-size: 0.9rem;
  }
  .search-box button:hover { color: #fff; }
  .content {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    padding: 12px;
    gap: 10px;
  }
  .chips {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    flex-shrink: 0;
  }
  .chip {
    background: #272727;
    border: 1px solid #3f3f3f;
    border-radius: 14px;
    color: #f1f1f1;
    font-size: 0.75rem;
    padding: 4px 10px;
    cursor: pointer;
    transition: all 0.15s;
    user-select: none;
  }
  .chip:hover { background: #ff0000; color: #fff; border-color: #ff0000; }
  .player-wrapper {
    width: 100%;
    aspect-ratio: 16 / 9;
    min-height: 200px;
    max-height: 360px;
    background: #000;
    border-radius: 8px;
    overflow: hidden;
    flex-shrink: 0;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
  }
  .player-frame {
    width: 100%;
    height: 100%;
    border: none;
  }
  .results-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex: 1;
  }
  .results-title {
    font-size: 0.82rem;
    color: #aaa;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .results-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .video-card {
    display: flex;
    gap: 10px;
    background: #1e1e1e;
    border: 1px solid #333;
    border-radius: 6px;
    padding: 8px;
    cursor: pointer;
    transition: background 0.15s;
    align-items: center;
  }
  .video-card:hover { background: #2a2a2a; border-color: #555; }
  .video-card.active { border-color: #ff0000; background: #2d1818; }
  .video-thumb {
    width: 90px;
    height: 54px;
    object-fit: cover;
    border-radius: 4px;
    background: #111;
    flex-shrink: 0;
  }
  .video-info {
    flex: 1;
    min-width: 0;
  }
  .video-name {
    font-size: 0.82rem;
    font-weight: 500;
    color: #fff;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    margin-bottom: 3px;
  }
  .video-meta {
    font-size: 0.72rem;
    color: #aaa;
  }
</style>
</head>
<body>
<div class="header">
  <div class="logo" id="homeLogo">▶ YouTube</div>
  <form class="search-box" id="ytForm">
    <input type="text" id="ytInput" placeholder="Search videos or paste YouTube link..." />
    <button type="submit">🔍</button>
  </form>
</div>
<div class="content">
  <div class="chips">
    <span class="chip" data-query="ICT trading strategy">📈 ICT Trading</span>
    <span class="chip" data-query="Lofi hip hop radio beats to relax">🎵 Lofi Hip Hop</span>
    <span class="chip" data-query="Chill lofi beats">☕ Chill Beats</span>
    <span class="chip" data-id="dQw4w9WgXcQ">🕺 Rick Astley</span>
    <span class="chip" data-query="Relaxing piano music study">🎹 Piano</span>
    <span class="chip" data-query="NASA space live stream">🚀 NASA Space</span>
  </div>
  <div class="player-wrapper">
    <iframe id="mainPlayer" class="player-frame" src="https://www.youtube-nocookie.com/embed/jfKfPfyJRdk?autoplay=0&rel=0" allowfullscreen allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"></iframe>
  </div>
  <div class="results-section" id="resultsSection">
    <div class="results-title" id="resultsHeading">Recommended Videos</div>
    <div class="results-list" id="resultsList"></div>
  </div>
</div>
<script>
  const form = document.getElementById('ytForm');
  const input = document.getElementById('ytInput');
  const player = document.getElementById('mainPlayer');
  const resultsList = document.getElementById('resultsList');
  const resultsHeading = document.getElementById('resultsHeading');
  const homeLogo = document.getElementById('homeLogo');

  function extractId(val) {
    if (!val) return null;
    const m = val.match(/(?:youtube\\.com\\/(?:watch\\?(?:.*&)?v=|shorts\\/|embed\\/|v\\/)|youtu\\.be\\/|youtube-nocookie\\.com\\/embed\\/)([\\w-]{6,})/i);
    if (m) return m[1];
    if (/^[\\w-]{11}$/.test(val.trim())) return val.trim();
    return null;
  }

  function playVideo(id, title) {
    if (!id) return;
    player.src = 'https://www.youtube-nocookie.com/embed/' + id + '?autoplay=1&rel=0';
    document.querySelectorAll('.video-card').forEach(c => {
      c.classList.toggle('active', c.dataset.id === id);
    });
  }

  async function searchVideos(query) {
    if (!query) return;
    const directId = extractId(query);
    if (directId) {
      playVideo(directId);
      resultsHeading.textContent = 'Playing Direct Video';
      resultsList.innerHTML = '<div style="color: #aaa; font-size: 0.8rem; padding: 6px;">Playing video ID: ' + directId + '</div>';
      return;
    }

    resultsHeading.textContent = 'Searching for "' + query + '"...';
    resultsList.innerHTML = '<div style="color: #888; font-size: 0.8rem; padding: 8px;">Loading YouTube search results...</div>';

    try {
      const res = await fetch('/api/youtube-search?q=' + encodeURIComponent(query));
      const data = await res.json();
      if (data && data.ok && Array.isArray(data.results) && data.results.length > 0) {
        resultsHeading.textContent = 'Results for "' + query + '" (' + data.results.length + ')';
        resultsList.innerHTML = '';
        
        // Auto-play the first video
        playVideo(data.results[0].id);

        data.results.forEach((item, idx) => {
          const card = document.createElement('div');
          card.className = 'video-card' + (idx === 0 ? ' active' : '');
          card.dataset.id = item.id;
          card.innerHTML = 
            '<img class="video-thumb" src="' + (item.thumbnail || 'https://i.ytimg.com/vi/' + item.id + '/hqdefault.jpg') + '" alt="" />' +
            '<div class="video-info">' +
              '<div class="video-name">' + (item.title || 'Video') + '</div>' +
              '<div class="video-meta">' + (item.channel ? item.channel + ' · ' : '') + (item.duration || 'Watch Video') + '</div>' +
            '</div>';
          card.addEventListener('click', () => {
            playVideo(item.id);
          });
          resultsList.appendChild(card);
        });
      } else {
        resultsHeading.textContent = 'No Direct Video Results';
        resultsList.innerHTML = '<div style="color: #888; font-size: 0.8rem; padding: 8px;">No videos found. Try a different search term or paste a direct YouTube video URL.</div>';
      }
    } catch(e) {
      resultsHeading.textContent = 'Search Error';
      resultsList.innerHTML = '<div style="color: #c9302c; font-size: 0.8rem; padding: 8px;">Could not search YouTube. Please check network.</div>';
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const val = input.value.trim();
    if (val) searchVideos(val);
  });

  homeLogo.addEventListener('click', () => {
    input.value = '';
    searchVideos('Lofi hip hop beats');
  });

  document.querySelectorAll('.chip').forEach(c => {
    c.addEventListener('click', () => {
      const id = c.dataset.id;
      const query = c.dataset.query;
      if (id) {
        playVideo(id);
      } else if (query) {
        input.value = query;
        searchVideos(query);
      }
    });
  });
</script>
</body>
</html>`;
  res.send(html);
});

app.get('/api/portal/search', (req, res) => {
  const query = typeof req.query.q === 'string' ? req.query.q : '';
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.set('X-Frame-Options', 'ALLOWALL');
  res.set('Access-Control-Allow-Origin', '*');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Web Search Portal</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: Georgia, 'Times New Roman', serif;
    background: #fdfbf7;
    color: #2c2416;
    padding: 16px;
    height: 100vh;
    display: flex;
    flex-direction: column;
  }
  .search-bar {
    display: flex;
    gap: 8px;
    margin-bottom: 14px;
  }
  .search-input {
    flex: 1;
    padding: 8px 12px;
    border: 1px solid #c9b68a;
    border-radius: 6px;
    font-family: inherit;
    font-size: 0.9rem;
    outline: none;
    background: #fff;
  }
  .search-btn {
    background: #b8935a;
    color: #fff;
    border: 1px solid #9c7b45;
    border-radius: 6px;
    padding: 8px 16px;
    cursor: pointer;
    font-family: inherit;
  }
  .results {
    flex: 1;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .result-card {
    background: #f4edde;
    border: 1px solid #dfd3ba;
    border-radius: 6px;
    padding: 10px 14px;
  }
  .result-title { font-weight: bold; font-size: 0.95rem; color: #2c2416; margin-bottom: 4px; }
  .result-title a { color: #8b5a2b; text-decoration: none; }
  .result-title a:hover { text-decoration: underline; }
  .result-snippet { font-size: 0.82rem; color: #5a4b35; line-height: 1.35; }
</style>
</head>
<body>
<form class="search-bar" id="sForm">
  <input type="text" class="search-input" id="sInput" value="${escapeHtml(query)}" placeholder="Search the web..." />
  <button type="submit" class="search-btn">Search</button>
</form>
<div class="results" id="resultsList">
  <div style="color: #7a6b55; font-size: 0.88rem;">Type a query above to search.</div>
</div>
<script>
  const form = document.getElementById('sForm');
  const input = document.getElementById('sInput');
  const results = document.getElementById('resultsList');

  async function doSearch(q) {
    if (!q) return;
    results.innerHTML = '<div style="color: #b8935a;">Searching...</div>';
    try {
      const res = await fetch('/api/search?q=' + encodeURIComponent(q));
      const data = await res.json();
      if (data && data.ok && data.results && data.results.length > 0) {
        results.innerHTML = '';
        data.results.forEach(r => {
          const div = document.createElement('div');
          div.className = 'result-card';
          div.innerHTML = '<div class="result-title"><a href="' + (r.url||'#') + '" target="_blank">' + (r.title||'') + '</a></div>' +
                          '<div class="result-snippet">' + (r.snippet||'') + '</div>';
          results.appendChild(div);
        });
      } else {
        results.innerHTML = '<div style="color: #7a6b55;">No direct instant results found. <a href="https://www.google.com/search?q=' + encodeURIComponent(q) + '" target="_blank">Search on Google ↗</a></div>';
      }
    } catch(e) {
      results.innerHTML = '<div style="color: #c9302c;">Search failed. Please check network.</div>';
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    doSearch(input.value.trim());
  });

  if (input.value.trim()) doSearch(input.value.trim());
</script>
</body>
</html>`;
  res.send(html);
});

app.get('/api/proxy', (req, res) => {
  const targetUrl = typeof req.query.url === 'string' ? req.query.url : '';
  if (!targetUrl) return res.status(400).json({ error: 'Missing url parameter' });
  streamProxy(targetUrl, 8, res);
});

// ---------- generic API / subresource proxy (handles GET, POST, PUT, OPTIONS, etc.) ----------
app.all('/api/proxy-api', (req, res) => {
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

// ---------- search API (Method 4: DuckDuckGo / Instant Web Search) ----------
app.get('/api/search', (req, res) => {
  const query = typeof req.query.q === 'string' ? req.query.q.trim() : '';
  if (!query) return res.json({ ok: true, results: [] });

  const ddgUrl = `https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&skip_disambig=1`;
  const reqUrl = new URL(ddgUrl);

  https.get(reqUrl, { headers: { 'User-Agent': PROXY_USER_AGENT }, timeout: 8000 }, (proxyRes) => {
    let raw = '';
    proxyRes.on('data', (c) => { raw += c; });
    proxyRes.on('end', () => {
      try {
        const json = JSON.parse(raw);
        const results = [];
        if (json.Heading && json.AbstractURL) {
          results.push({
            title: json.Heading,
            snippet: json.AbstractText || json.Abstract || '',
            url: json.AbstractURL,
            icon: json.Image || '',
            source: json.AbstractSource || 'DuckDuckGo'
          });
        }
        if (Array.isArray(json.RelatedTopics)) {
          for (const topic of json.RelatedTopics) {
            if (topic.Text && topic.FirstURL) {
              results.push({
                title: topic.Text.split(' - ')[0] || topic.Text,
                snippet: topic.Text,
                url: topic.FirstURL,
                icon: topic.Icon ? topic.Icon.URL : '',
                source: 'Web'
              });
            } else if (Array.isArray(topic.Topics)) {
              for (const sub of topic.Topics) {
                if (sub.Text && sub.FirstURL) {
                  results.push({
                    title: sub.Text.split(' - ')[0] || sub.Text,
                    snippet: sub.Text,
                    url: sub.FirstURL,
                    icon: sub.Icon ? sub.Icon.URL : '',
                    source: 'Web'
                  });
                }
              }
            }
          }
        }
        res.json({ ok: true, results: results.slice(0, 15) });
      } catch (e) {
        res.json({ ok: true, results: [] });
      }
    });
  }).on('error', () => {
    res.json({ ok: true, results: [] });
  });
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

app.get('/api/proxy-asset', (req, res) => {
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

if (require.main === module) {
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



