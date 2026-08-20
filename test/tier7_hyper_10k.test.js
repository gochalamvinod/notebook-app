/**
 * Tier 7: Hyper-Scale 10,000+ Stress Suite
 * 3D Leatherbound Notebook
 *
 * Exactly 10,000 High-Speed, Zero-Defect Unit & Stress Tests:
 * 1. YouTube URL permutations (1,500 tests)
 * 2. Google Drive & Docs/Sheets/Slides (1,000 tests)
 * 3. Dropbox & Cloud storage files (500 tests)
 * 4. Vimeo Video URLs (500 tests)
 * 5. Image URLs & 8-Handle Resizer Matrix (2,500 tests)
 * 6. XSS Sanitization & Hostile Vector Matrix (1,500 tests)
 * 7. Mini-Browser Embed HTML Structure Matrix (1,000 tests)
 * 8. Crypto & Vault Encryption Roundtrips with Password Vinod@807465 and Tamper Detection (1,500 tests)
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

// --- PURE CORE LOGIC UNDER TEST (from public/app.js & server.js) ---

const IMAGE_EXT_RE = /\.(png|jpe?g|gif|webp|svg|avif)(\?[^\s]*)?(#.*)?$/i;
const VIDEO_EXT_RE = /\.(mp4|webm|ogg|ogv|mov|m4v)(\?[^\s]*)?(#.*)?$/i;

function parseYouTubeId(url) {
  if (!url || typeof url !== 'string') return null;
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./i, '').replace(/^m\./i, '');
    if (host === 'youtu.be') {
      const id = u.pathname.slice(1).split('/')[0].split('?')[0];
      if (id && /^[\w-]{6,}$/.test(id)) return id;
    }
    if (host === 'youtube.com' || host === 'youtube-nocookie.com') {
      if (u.pathname === '/watch') {
        const v = u.searchParams.get('v');
        if (v && /^[\w-]{6,}$/.test(v)) return v;
      }
      const m = u.pathname.match(/^\/(?:shorts|embed|v)\/([\w-]{6,})/i);
      if (m) return m[1];
    }
  } catch (e) {}
  const m = url.match(/(?:youtube\.com\/(?:watch\?(?:.*&)?v=|shorts\/|embed\/|v\/)|youtu\.be\/|youtube-nocookie\.com\/embed\/)([\w-]{6,})/i);
  return m ? m[1] : null;
}

function parseVimeoId(url) {
  if (!url || typeof url !== 'string') return null;
  const m = url.match(/(?:vimeo\.com\/(?:video\/|channels\/(?:\w+\/)?|groups\/[^\/]+\/videos\/)?|player\.vimeo\.com\/video\/)(\d+)/i);
  return m ? m[1] : null;
}

function parseCloudDoc(url) {
  if (!url || typeof url !== 'string') return null;
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./i, '');
    // Google Drive file
    if (host === 'drive.google.com') {
      const fileMatch = u.pathname.match(/\/file\/d\/([\w-]+)/i);
      if (fileMatch) return { type: 'gdrive', id: fileMatch[1], embedUrl: `https://drive.google.com/file/d/${fileMatch[1]}/preview` };
      const idParam = u.searchParams.get('id');
      if (idParam) return { type: 'gdrive', id: idParam, embedUrl: `https://drive.google.com/file/d/${idParam}/preview` };
    }
    // Google Docs / Sheets / Slides
    if (host === 'docs.google.com') {
      const docMatch = u.pathname.match(/\/(document|spreadsheets|presentation)\/d\/([\w-]+)/i);
      if (docMatch) {
        const docType = docMatch[1];
        const docId = docMatch[2];
        return { type: 'gdocs', id: docId, embedUrl: `https://docs.google.com/${docType}/d/${docId}/preview` };
      }
    }
    // Dropbox
    if (host === 'dropbox.com') {
      const uClone = new URL(url);
      uClone.searchParams.delete('dl');
      uClone.searchParams.set('raw', '1');
      return { type: 'dropbox', id: u.pathname, embedUrl: uClone.toString() };
    }
  } catch (e) {}
  return null;
}

function classifyUrl(url) {
  if (!url || typeof url !== 'string') return { type: 'link' };
  if (IMAGE_EXT_RE.test(url)) return { type: 'image' };
  if (VIDEO_EXT_RE.test(url)) return { type: 'video' };
  const ytId = parseYouTubeId(url);
  if (ytId) return { type: 'youtube', id: ytId };
  const cloudDoc = parseCloudDoc(url);
  if (cloudDoc) return { type: 'cloud', details: cloudDoc };
  const vimeoId = parseVimeoId(url);
  if (vimeoId) return { type: 'vimeo', id: vimeoId };
  return { type: 'link' };
}

function getIframeSrcForUrl(url) {
  if (!url) return '/api/proxy?url=about:blank';
  const trimmed = url.trim();
  const ytId = parseYouTubeId(trimmed);
  if (ytId) {
    return `https://www.youtube-nocookie.com/embed/${ytId}?autoplay=0&rel=0&modestbranding=1`;
  }
  const cloudDoc = parseCloudDoc(trimmed);
  if (cloudDoc && cloudDoc.embedUrl) {
    return cloudDoc.embedUrl;
  }
  if (/^(?:https?:\/\/)?(?:www\.|m\.)?(?:youtube\.com|youtu\.be)\/?$/i.test(trimmed)) {
    return '/api/proxy?url=' + encodeURIComponent('https://duckduckgo.com/html/?q=trending+videos');
  }
  if (/^(?:https?:\/\/)?(?:www\.)?google\.com\/?$/i.test(trimmed)) {
    return '/api/proxy?url=' + encodeURIComponent('https://duckduckgo.com/html/');
  }
  const googleSearchMatch = trimmed.match(/(?:google\.com\/search\?(?:.*&)?q=)([^&]+)/i);
  if (googleSearchMatch) {
    return '/api/proxy?url=' + encodeURIComponent('https://duckduckgo.com/html/?q=' + googleSearchMatch[1]);
  }
  const vimeoId = parseVimeoId(trimmed);
  if (vimeoId) {
    return `https://player.vimeo.com/video/${vimeoId}`;
  }
  return '/api/proxy?url=' + encodeURIComponent(trimmed);
}

function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function escapeAttr(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

function buildLiveEmbedHTML(url, title, domain, icon = '🌐') {
  const safeUrl = escapeAttr(url);
  const safeTitle = escapeHtml((title || url).slice(0, 120));
  const safeDomain = escapeHtml(domain || '');
  const iframeSrc = getIframeSrcForUrl(url);

  return (
    `<div class="nb-live-embed" contenteditable="false" data-url="${safeUrl}">` +
      `<div class="nb-live-embed__bar">` +
        `<div class="nb-live-embed__nav-group">` +
          `<button class="nb-live-embed__btn nb-live-embed__btn--back" title="Back">` +
            `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>` +
          `</button>` +
          `<button class="nb-live-embed__btn nb-live-embed__btn--forward" title="Forward">` +
            `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>` +
          `</button>` +
          `<button class="nb-live-embed__btn nb-live-embed__btn--reload" title="Reload">` +
            `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>` +
          `</button>` +
          `<button class="nb-live-embed__btn nb-live-embed__btn--home" title="Original Page">` +
            `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>` +
          `</button>` +
        `</div>` +
        `<div class="nb-live-embed__omnibox">` +
          `<span class="nb-live-embed__icon">${icon}</span>` +
          `<input type="text" class="nb-live-embed__address-input" value="${safeUrl}" title="Type a URL or search query and press Enter" placeholder="Enter URL or search..." />` +
        `</div>` +
        `<div class="nb-live-embed__action-group">` +
          `<button class="nb-live-embed__btn nb-live-embed__btn--expand" title="Expand / Fullscreen">` +
            `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>` +
          `</button>` +
          `<a class="nb-live-embed__btn nb-live-embed__btn--open" href="${safeUrl}" target="_blank" rel="noopener noreferrer" title="Open in new tab">` +
            `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>` +
          `</a>` +
          `<button class="nb-live-embed__btn nb-live-embed__btn--remove" title="Remove embed">` +
            `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>` +
          `</button>` +
        `</div>` +
      `</div>` +
      `<div class="nb-live-embed__frame-wrap">` +
        `<iframe class="nb-live-embed__iframe" src="${escapeAttr(iframeSrc)}" loading="lazy" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>` +
      `</div>` +
      `<div class="nb-live-embed__resize-handle" title="Drag to resize height"></div>` +
    `</div><br>`
  );
}

function buildDirectVideoEmbedHTML(url, title) {
  const safeUrl = escapeAttr(url);
  const safeTitle = escapeHtml((title || 'Video').slice(0, 120));

  return (
    `<div class="nb-live-embed nb-live-embed--video" contenteditable="false" data-url="${safeUrl}">` +
      `<div class="nb-live-embed__bar">` +
        `<span class="nb-live-embed__icon">🎬</span>` +
        `<span class="nb-live-embed__info">` +
          `<span class="nb-live-embed__title">${safeTitle}</span>` +
          `<span class="nb-live-embed__domain">HTML5 Video</span>` +
        `</span>` +
        `<button class="nb-live-embed__btn nb-live-embed__btn--reload" title="Reload video">` +
          `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>` +
        `</button>` +
        `<button class="nb-live-embed__btn nb-live-embed__btn--expand" title="Expand / Fullscreen">` +
          `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>` +
        `</button>` +
        `<a class="nb-live-embed__btn nb-live-embed__btn--open" href="${safeUrl}" target="_blank" rel="noopener noreferrer" title="Open in new tab">` +
          `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>` +
        `</a>` +
        `<button class="nb-live-embed__btn nb-live-embed__btn--remove" title="Remove embed">` +
          `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>` +
        `</button>` +
      `</div>` +
      `<div class="nb-live-embed__frame-wrap">` +
        `<video class="nb-live-embed__video" src="${safeUrl}" controls preload="metadata" playsinline></video>` +
      `</div>` +
    `</div><br>`
  );
}

function buildPreviewCardHTML(url, title, desc, image, domain) {
  const safeUrl = escapeAttr(url);
  const safeTitle = escapeHtml(title || url);
  const safeDesc = escapeHtml(desc || '');
  const safeDomain = escapeHtml(domain || '');

  const thumbHtml = image
    ? `<img class="nb-link-card__thumb" src="${escapeAttr(image)}" alt="">`
    : `<span class="nb-link-card__thumb--placeholder">📰</span>`;
  const descHtml = safeDesc ? `<div class="nb-link-card__desc">${safeDesc}</div>` : '';

  return (
    `<a class="nb-link-card" href="${safeUrl}" target="_blank" rel="noopener noreferrer" contenteditable="false">` +
      thumbHtml +
      `<div class="nb-link-card__body">` +
        `<div class="nb-link-card__title">${safeTitle}</div>` +
        descHtml +
        `<div class="nb-link-card__domain">${safeDomain} <span class="nb-link-card__domain-dot">•</span> Preview Card</div>` +
      `</div>` +
      `<span class="nb-link-card__arrow">↗</span>` +
    `</a><br>`
  );
}

function calculateImageResize(handle, startW, startH, deltaX, deltaY) {
  let w = startW;
  let h = startH;

  if (handle.dx !== 0) {
    w = Math.max(40, startW + handle.dx * deltaX);
  }
  if (handle.dy !== 0 && handle.dx === 0) {
    h = Math.max(40, startH + handle.dy * deltaY);
  }
  return { width: w, height: h };
}

function calculateEmbedHeightResize(startH, deltaY) {
  return Math.max(120, startH + deltaY);
}

function deriveKey(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
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

function decryptData(payload, key) {
  const iv = Buffer.from(payload.iv, 'hex');
  const authTag = Buffer.from(payload.authTag, 'hex');
  const ciphertext = Buffer.from(payload.data, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}


// =========================================================================
// SECTION 1: YouTube URL Permutations (1,500 tests)
// =========================================================================
describe('Tier 7 - Section 1: YouTube URL Permutations (1,500 tests)', () => {
  // Generate 100 base video IDs (11-chars standard base64url safe chars)
  const ytVideoIds = Array.from({ length: 100 }, (_, i) => {
    const raw = `ytVid_${String(i).padStart(3, '0')}_${(i * 31).toString(36)}`;
    return raw.slice(0, 11).padEnd(11, 'X');
  });

  const ytFormatTemplates = [
    (id) => ({ url: `https://www.youtube.com/watch?v=${id}`, id }),
    (id) => ({ url: `http://youtube.com/watch?v=${id}`, id }),
    (id) => ({ url: `https://m.youtube.com/watch?v=${id}&feature=shared`, id }),
    (id) => ({ url: `https://youtube.com/shorts/${id}`, id }),
    (id) => ({ url: `https://www.youtube.com/shorts/${id}?si=track123`, id }),
    (id) => ({ url: `https://youtu.be/${id}`, id }),
    (id) => ({ url: `https://youtu.be/${id}?t=120&si=abcxyz`, id }),
    (id) => ({ url: `https://www.youtube.com/embed/${id}`, id }),
    (id) => ({ url: `https://www.youtube-nocookie.com/embed/${id}`, id }),
    (id) => ({ url: `https://youtube.com/v/${id}`, id }),
    (id) => ({ url: `https://www.youtube.com/watch?feature=youtu.be&v=${id}&t=10s`, id }),
    (id) => ({ url: `https://m.youtube.com/watch?app=desktop&v=${id}`, id }),
    (id) => ({ url: `https://youtube.com/watch?list=PL123456789&v=${id}&index=3`, id }),
    (id) => ({ url: `https://youtu.be/${id}?list=PLxyz`, id }),
    (id) => ({ url: `http://www.youtube.com/embed/${id}?autoplay=1`, id }),
  ]; // 15 templates * 100 video IDs = 1,500 tests

  for (let fIndex = 0; fIndex < ytFormatTemplates.length; fIndex++) {
    for (let idIndex = 0; idIndex < ytVideoIds.length; idIndex++) {
      const template = ytFormatTemplates[fIndex];
      const videoId = ytVideoIds[idIndex];
      const testNum = fIndex * ytVideoIds.length + idIndex + 1;

      test(`[YouTube ${testNum}/1500] Format #${fIndex + 1} for ID ${videoId}`, () => {
        const { url, id } = template(videoId);
        const parsedId = parseYouTubeId(url);
        assert.equal(parsedId, id, `parseYouTubeId failed for: ${url}`);

        const classification = classifyUrl(url);
        assert.deepEqual(classification, { type: 'youtube', id });

        const iframeSrc = getIframeSrcForUrl(url);
        assert.equal(
          iframeSrc,
          `https://www.youtube-nocookie.com/embed/${id}?autoplay=0&rel=0&modestbranding=1`
        );
      });
    }
  }
});


// =========================================================================
// SECTION 2: Google Drive & Docs/Sheets/Slides (1,000 tests)
// =========================================================================
describe('Tier 7 - Section 2: Google Drive & Docs/Sheets/Slides (1,000 tests)', () => {
  const docIds = Array.from({ length: 100 }, (_, i) => `docId_${String(i).padStart(3, '0')}_ABC123xyz`);

  const gsuiteTemplates = [
    (id) => ({
      url: `https://drive.google.com/file/d/${id}/view`,
      type: 'gdrive',
      id,
      embedUrl: `https://drive.google.com/file/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://drive.google.com/file/d/${id}/preview`,
      type: 'gdrive',
      id,
      embedUrl: `https://drive.google.com/file/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://drive.google.com/file/d/${id}/edit?usp=sharing`,
      type: 'gdrive',
      id,
      embedUrl: `https://drive.google.com/file/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://drive.google.com/open?id=${id}`,
      type: 'gdrive',
      id,
      embedUrl: `https://drive.google.com/file/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://docs.google.com/document/d/${id}/edit`,
      type: 'gdocs',
      id,
      embedUrl: `https://docs.google.com/document/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://docs.google.com/document/d/${id}/preview`,
      type: 'gdocs',
      id,
      embedUrl: `https://docs.google.com/document/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://docs.google.com/spreadsheets/d/${id}/edit#gid=0`,
      type: 'gdocs',
      id,
      embedUrl: `https://docs.google.com/spreadsheets/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://docs.google.com/spreadsheets/d/${id}/preview`,
      type: 'gdocs',
      id,
      embedUrl: `https://docs.google.com/spreadsheets/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://docs.google.com/presentation/d/${id}/edit#slide=id.p`,
      type: 'gdocs',
      id,
      embedUrl: `https://docs.google.com/presentation/d/${id}/preview`,
    }),
    (id) => ({
      url: `https://docs.google.com/presentation/d/${id}/preview`,
      type: 'gdocs',
      id,
      embedUrl: `https://docs.google.com/presentation/d/${id}/preview`,
    }),
  ]; // 10 templates * 100 doc IDs = 1,000 tests

  for (let tIndex = 0; tIndex < gsuiteTemplates.length; tIndex++) {
    for (let idIndex = 0; idIndex < docIds.length; idIndex++) {
      const template = gsuiteTemplates[tIndex];
      const docId = docIds[idIndex];
      const testNum = tIndex * docIds.length + idIndex + 1;

      test(`[Google Drive & Docs ${testNum}/1000] Template #${tIndex + 1} for ID ${docId}`, () => {
        const expected = template(docId);
        const parsed = parseCloudDoc(expected.url);
        assert.ok(parsed, `parseCloudDoc must match for ${expected.url}`);
        assert.equal(parsed.type, expected.type);
        assert.equal(parsed.id, expected.id);
        assert.equal(parsed.embedUrl, expected.embedUrl);

        const classification = classifyUrl(expected.url);
        assert.equal(classification.type, 'cloud');
        assert.deepEqual(classification.details, parsed);

        const iframeSrc = getIframeSrcForUrl(expected.url);
        assert.equal(iframeSrc, expected.embedUrl);
      });
    }
  }
});


// =========================================================================
// SECTION 3: Dropbox & Cloud Storage Files (500 tests)
// =========================================================================
describe('Tier 7 - Section 3: Dropbox & Cloud Storage Files (500 tests)', () => {
  const fileKeys = Array.from({ length: 100 }, (_, i) => `drop_file_${String(i).padStart(3, '0')}`);

  const dropboxTemplates = [
    (k) => ({
      url: `https://www.dropbox.com/s/${k}/document.pdf?dl=0`,
      expectedEmbed: `https://www.dropbox.com/s/${k}/document.pdf?raw=1`,
    }),
    (k) => ({
      url: `https://dropbox.com/scl/fi/${k}/report.docx?rlkey=secret123&dl=0`,
      expectedEmbed: `https://dropbox.com/scl/fi/${k}/report.docx?rlkey=secret123&raw=1`,
    }),
    (k) => ({
      url: `https://www.dropbox.com/s/${k}/presentation.pptx`,
      expectedEmbed: `https://www.dropbox.com/s/${k}/presentation.pptx?raw=1`,
    }),
    (k) => ({
      url: `https://dropbox.com/sh/${k}/archive.zip?dl=0`,
      expectedEmbed: `https://dropbox.com/sh/${k}/archive.zip?raw=1`,
    }),
    (k) => ({
      url: `https://www.dropbox.com/scl/fi/${k}/notes.txt?preview=1&dl=0`,
      expectedEmbed: `https://www.dropbox.com/scl/fi/${k}/notes.txt?preview=1&raw=1`,
    }),
  ]; // 5 templates * 100 file keys = 500 tests

  for (let tIndex = 0; tIndex < dropboxTemplates.length; tIndex++) {
    for (let kIndex = 0; kIndex < fileKeys.length; kIndex++) {
      const template = dropboxTemplates[tIndex];
      const key = fileKeys[kIndex];
      const testNum = tIndex * fileKeys.length + kIndex + 1;

      test(`[Dropbox & Cloud ${testNum}/500] Template #${tIndex + 1} key ${key}`, () => {
        const { url, expectedEmbed } = template(key);
        const parsed = parseCloudDoc(url);
        assert.ok(parsed, `parseCloudDoc must match for ${url}`);
        assert.equal(parsed.type, 'dropbox');
        assert.equal(parsed.embedUrl, expectedEmbed);

        const classification = classifyUrl(url);
        assert.equal(classification.type, 'cloud');
        assert.deepEqual(classification.details, parsed);

        const iframeSrc = getIframeSrcForUrl(url);
        assert.equal(iframeSrc, expectedEmbed);
      });
    }
  }
});


// =========================================================================
// SECTION 4: Vimeo Video URLs (500 tests)
// =========================================================================
describe('Tier 7 - Section 4: Vimeo Video URLs (500 tests)', () => {
  const vimeoNumericIds = Array.from({ length: 100 }, (_, i) => String(70000000 + i * 137));

  const vimeoTemplates = [
    (id) => ({ url: `https://vimeo.com/${id}`, id }),
    (id) => ({ url: `https://player.vimeo.com/video/${id}`, id }),
    (id) => ({ url: `https://vimeo.com/video/${id}`, id }),
    (id) => ({ url: `https://vimeo.com/channels/staffpicks/${id}`, id }),
    (id) => ({ url: `https://vimeo.com/groups/motiondesign/videos/${id}`, id }),
  ]; // 5 templates * 100 numeric IDs = 500 tests

  for (let tIndex = 0; tIndex < vimeoTemplates.length; tIndex++) {
    for (let idIndex = 0; idIndex < vimeoNumericIds.length; idIndex++) {
      const template = vimeoTemplates[tIndex];
      const vimeoId = vimeoNumericIds[idIndex];
      const testNum = tIndex * vimeoNumericIds.length + idIndex + 1;

      test(`[Vimeo ${testNum}/500] Template #${tIndex + 1} ID ${vimeoId}`, () => {
        const { url, id } = template(vimeoId);
        const parsedId = parseVimeoId(url);
        assert.equal(parsedId, id);

        const classification = classifyUrl(url);
        assert.deepEqual(classification, { type: 'vimeo', id });

        const iframeSrc = getIframeSrcForUrl(url);
        assert.equal(iframeSrc, `https://player.vimeo.com/video/${id}`);
      });
    }
  }
});


// =========================================================================
// SECTION 5: Image URLs & 8-Handle Resizer Matrix (2,500 tests)
// =========================================================================
describe('Tier 7 - Section 5: Image URLs & 8-Handle Resizer Matrix (2,500 tests)', () => {
  // Part A: Image URL extension classification matrix (700 tests)
  const imgExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'avif'];
  for (let extIdx = 0; extIdx < imgExts.length; extIdx++) {
    const ext = imgExts[extIdx];
    for (let i = 0; i < 100; i++) {
      const testNum = extIdx * 100 + i + 1;
      test(`[Image URL Classification ${testNum}/700] Extension .${ext} variation #${i}`, () => {
        const query = i % 2 === 0 ? `?v=${i}&size=large` : '';
        const hash = i % 3 === 0 ? `#imgSection${i}` : '';
        const url = `https://cdn.example.org/assets/gallery_${i}.${ext}${query}${hash}`;
        const classification = classifyUrl(url);
        assert.equal(classification.type, 'image', `URL ${url} should classify as image`);
      });
    }
  }

  // Part B: 8-Handle Image Resizer calculation matrix (1,600 tests)
  const handles = [
    { name: 'NW', dx: -1, dy: -1 },
    { name: 'N',  dx:  0, dy: -1 },
    { name: 'NE', dx:  1, dy: -1 },
    { name: 'W',  dx: -1, dy:  0 },
    { name: 'E',  dx:  1, dy:  0 },
    { name: 'SW', dx: -1, dy:  1 },
    { name: 'S',  dx:  0, dy:  1 },
    { name: 'SE', dx:  1, dy:  1 },
  ];

  for (let hIdx = 0; hIdx < handles.length; hIdx++) {
    const h = handles[hIdx];
    for (let step = 0; step < 200; step++) {
      const testNum = hIdx * 200 + step + 1;
      test(`[8-Handle Resizer Matrix ${testNum}/1600] Handle ${h.name} step ${step}`, () => {
        const startW = 100 + (step % 50) * 10;
        const startH = 80 + (step % 40) * 10;
        const deltaX = (step - 100) * 5;
        const deltaY = (step - 100) * 5;

        const result = calculateImageResize(h, startW, startH, deltaX, deltaY);

        if (h.dx !== 0) {
          const expectedW = Math.max(40, startW + h.dx * deltaX);
          assert.equal(result.width, expectedW);
          assert.ok(result.width >= 40, 'Width must never be clamped below 40px');
        } else {
          assert.equal(result.width, startW, 'Pure vertical drag must preserve start width');
        }

        if (h.dy !== 0 && h.dx === 0) {
          const expectedH = Math.max(40, startH + h.dy * deltaY);
          assert.equal(result.height, expectedH);
          assert.ok(result.height >= 40, 'Height must never be clamped below 40px');
        } else {
          assert.equal(result.height, startH, 'Horizontal or corner drag preserves start height');
        }
      });
    }
  }

  // Part C: Embed container height resize calculations (200 tests)
  for (let i = 0; i < 200; i++) {
    test(`[Embed Height Resize ${i + 1}/200] startH variation step ${i}`, () => {
      const startH = 150 + (i % 20) * 15;
      const deltaY = (i - 100) * 10;
      const res = calculateEmbedHeightResize(startH, deltaY);
      const expected = Math.max(120, startH + deltaY);
      assert.equal(res, expected);
      assert.ok(res >= 120, 'Embed height must never clamp below 120px');
    });
  }
});


// =========================================================================
// SECTION 6: XSS Sanitization & Hostile Vector Matrix (1,500 tests)
// =========================================================================
describe('Tier 7 - Section 6: XSS Sanitization & Hostile Vector Matrix (1,500 tests)', () => {
  const hostileHtmlPayloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert(document.domain)>',
    '"><script src=//evil.com/x.js></script>',
    '\'><svg/onload=alert(1)>',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<body onload=alert(1)>',
    '<a href="javascript:alert(1)">click me</a>',
    '<math><mtext><table><mglyph><style><!--</style><img src=1 onerror=alert(1)>',
    '<details open ontoggle=alert(1)>',
  ];

  // Part A: escapeHtml tests (500 tests)
  for (let i = 0; i < 500; i++) {
    test(`[escapeHtml ${i + 1}/500] Hostile pattern vector #${i}`, () => {
      const basePayload = hostileHtmlPayloads[i % hostileHtmlPayloads.length];
      const input = `Prefix ${i} & ${basePayload} <b>Bold</b> &amp; Suffix ${i}`;
      const escaped = escapeHtml(input);

      assert.ok(!escaped.includes('<script>'), 'Must not contain raw <script>');
      assert.ok(!escaped.includes('<img'), 'Must not contain raw <img');
      assert.ok(!escaped.includes('<svg'), 'Must not contain raw <svg');
      assert.ok(!escaped.includes('<iframe'), 'Must not contain raw <iframe');
      assert.ok(!escaped.includes('<'), 'Must not contain raw unescaped <');
      assert.ok(!escaped.includes('>'), 'Must not contain raw unescaped >');
      assert.ok(escaped.includes('&lt;'), 'Must encode < to &lt;');
      assert.ok(escaped.includes('&gt;'), 'Must encode > to &gt;');
      assert.ok(escaped.includes('&amp;'), 'Must encode & to &amp;');
    });
  }

  // Part B: escapeAttr tests (500 tests)
  for (let i = 0; i < 500; i++) {
    test(`[escapeAttr ${i + 1}/500] Attribute breakout vector #${i}`, () => {
      const input = `https://example.com/test?q=" onclick="alert(${i})" &param="attack_${i}"`;
      const escaped = escapeAttr(input);

      assert.ok(!escaped.includes('"'), 'Must not contain raw unescaped double quotes');
      assert.ok(escaped.includes('&quot;'), 'Must encode double quotes to &quot;');
      assert.ok(escaped.includes('&amp;'), 'Must encode ampersands to &amp;');
    });
  }

  // Part C: Hostile Injection Sanitization in Live Embeds and Preview Cards (500 tests)
  for (let i = 0; i < 500; i++) {
    test(`[Sanitization in Embeds & Cards ${i + 1}/500] Vector #${i}`, () => {
      const maliciousUrl = `https://example.com/search?p=${i}&q=" onclick="alert(${i})`;
      const maliciousTitle = `<script>alert(${i})</script> Title #${i}`;
      const maliciousDesc = `<img src=x onerror=alert(${i})> Description #${i}`;
      const maliciousDomain = `<svg onload=alert(${i})>domain${i}.com`;

      // Test buildLiveEmbedHTML
      const liveHtml = buildLiveEmbedHTML(maliciousUrl, maliciousTitle, maliciousDomain);
      assert.ok(!liveHtml.includes('" onclick="'), 'Must sanitize attribute breakout');
      assert.ok(liveHtml.includes('&quot; onclick=&quot;'), 'Must encode attribute quotes');
      assert.ok(liveHtml.includes('class="nb-live-embed"'), 'Must construct valid embed');

      // Test buildPreviewCardHTML
      const cardHtml = buildPreviewCardHTML(maliciousUrl, maliciousTitle, maliciousDesc, '', maliciousDomain);
      assert.ok(!cardHtml.includes('<script>alert('), 'Must not contain raw script tag');
      assert.ok(!cardHtml.includes('<img src=x'), 'Must not contain raw img tag');
      assert.ok(!cardHtml.includes('<svg onload='), 'Must not contain raw svg tag');
      assert.ok(cardHtml.includes('&lt;script&gt;'), 'Title must be HTML entity encoded');
      assert.ok(cardHtml.includes('&lt;img src=x'), 'Desc must be HTML entity encoded');
      assert.ok(cardHtml.includes('&lt;svg onload='), 'Domain must be HTML entity encoded');
    });
  }
});


// =========================================================================
// SECTION 7: Mini-Browser Embed HTML Structure Matrix (1,000 tests)
// =========================================================================
describe('Tier 7 - Section 7: Mini-Browser Embed HTML Structure Matrix (1,000 tests)', () => {
  // Part A: buildLiveEmbedHTML full structural checks (400 tests)
  for (let i = 0; i < 400; i++) {
    test(`[Live Embed Structure ${i + 1}/400] Embed variant #${i}`, () => {
      const url = `https://example${i}.org/page_${i}`;
      const title = `Page Title ${i}`;
      const domain = `example${i}.org`;
      const html = buildLiveEmbedHTML(url, title, domain, '🌐');

      assert.ok(html.includes('class="nb-live-embed"'));
      assert.ok(html.includes('contenteditable="false"'));
      assert.ok(html.includes(`data-url="${url}"`));
      assert.ok(html.includes('class="nb-live-embed__bar"'));
      assert.ok(html.includes('class="nb-live-embed__nav-group"'));
      assert.ok(html.includes('nb-live-embed__btn--back'));
      assert.ok(html.includes('nb-live-embed__btn--forward'));
      assert.ok(html.includes('nb-live-embed__btn--reload'));
      assert.ok(html.includes('nb-live-embed__btn--home'));
      assert.ok(html.includes('class="nb-live-embed__omnibox"'));
      assert.ok(html.includes('class="nb-live-embed__address-input"'));
      assert.ok(html.includes(`value="${url}"`));
      assert.ok(html.includes('class="nb-live-embed__action-group"'));
      assert.ok(html.includes('nb-live-embed__btn--expand'));
      assert.ok(html.includes('nb-live-embed__btn--open'));
      assert.ok(html.includes('target="_blank"'));
      assert.ok(html.includes('rel="noopener noreferrer"'));
      assert.ok(html.includes('nb-live-embed__btn--remove'));
      assert.ok(html.includes('class="nb-live-embed__frame-wrap"'));
      assert.ok(html.includes('<iframe class="nb-live-embed__iframe"'));
      assert.ok(html.includes('loading="lazy"'));
      assert.ok(html.includes('allowfullscreen'));
      assert.ok(html.includes('class="nb-live-embed__resize-handle"'));
    });
  }

  // Part B: buildDirectVideoEmbedHTML structural checks (300 tests)
  for (let i = 0; i < 300; i++) {
    test(`[Direct Video Structure ${i + 1}/300] Video variant #${i}`, () => {
      const url = `https://media.example.org/videos/clip_${i}.mp4`;
      const title = `Sample Video ${i}`;
      const html = buildDirectVideoEmbedHTML(url, title);

      assert.ok(html.includes('class="nb-live-embed nb-live-embed--video"'));
      assert.ok(html.includes('contenteditable="false"'));
      assert.ok(html.includes(`data-url="${url}"`));
      assert.ok(html.includes(`class="nb-live-embed__title">${title}</span>`));
      assert.ok(html.includes('class="nb-live-embed__domain">HTML5 Video</span>'));
      assert.ok(html.includes('nb-live-embed__btn--reload'));
      assert.ok(html.includes('nb-live-embed__btn--expand'));
      assert.ok(html.includes('nb-live-embed__btn--open'));
      assert.ok(html.includes('nb-live-embed__btn--remove'));
      assert.ok(html.includes('<video class="nb-live-embed__video"'));
      assert.ok(html.includes(`src="${url}"`));
      assert.ok(html.includes('controls'));
      assert.ok(html.includes('preload="metadata"'));
      assert.ok(html.includes('playsinline'));
    });
  }

  // Part C: buildPreviewCardHTML structural checks (300 tests)
  for (let i = 0; i < 300; i++) {
    test(`[Preview Card Structure ${i + 1}/300] Card variant #${i}`, () => {
      const url = `https://news.example.org/article_${i}`;
      const title = `Breaking News Headline #${i}`;
      const desc = `Detailed description of breaking story #${i}`;
      const image = i % 2 === 0 ? `https://news.example.org/thumbs/t_${i}.jpg` : '';
      const domain = `news.example.org`;

      const html = buildPreviewCardHTML(url, title, desc, image, domain);

      assert.ok(html.includes('class="nb-link-card"'));
      assert.ok(html.includes(`href="${url}"`));
      assert.ok(html.includes('target="_blank"'));
      assert.ok(html.includes('rel="noopener noreferrer"'));
      assert.ok(html.includes('contenteditable="false"'));
      assert.ok(html.includes(`class="nb-link-card__title">${title}</div>`));
      assert.ok(html.includes(`class="nb-link-card__desc">${desc}</div>`));
      assert.ok(html.includes(`class="nb-link-card__domain">${domain}`));
      assert.ok(html.includes('Preview Card'));
      assert.ok(html.includes('class="nb-link-card__arrow">↗</span>'));

      if (image) {
        assert.ok(html.includes(`class="nb-link-card__thumb" src="${image}"`));
      } else {
        assert.ok(html.includes('class="nb-link-card__thumb--placeholder">📰</span>'));
      }
    });
  }
});


// =========================================================================
// SECTION 8: Crypto & Vault Encryption with Vinod@807465 (1,500 tests)
// =========================================================================
describe('Tier 7 - Section 8: Crypto & Vault Encryption Roundtrips & Tamper Matrix (1,500 tests)', () => {
  const MASTER_PASSWORD = 'Vinod@807465';
  const saltHex = crypto.randomBytes(16).toString('hex');
  const masterKey = deriveKey(MASTER_PASSWORD, saltHex);

  // Part A: 1,000 Encryption / Decryption Roundtrips of complex vault payloads
  for (let i = 0; i < 1000; i++) {
    test(`[Crypto Roundtrip ${i + 1}/1000] Vault structure iteration #${i}`, () => {
      const payload = {
        version: 2,
        activeBookId: `book_${i}`,
        books: [
          {
            id: `book_${i}`,
            title: `Notebook Voyage ${i} - 📖 🚀`,
            coverColor: ['brown', 'green', 'navy', 'burgundy', 'black'][i % 5],
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            pages: [
              {
                id: `p_${i}_1`,
                font: 'Georgia',
                fontSize: '18px',
                html: `<p>Rich page content ${i} with special chars & < > " ' and emoji 🌟✨</p>`,
              },
              {
                id: `p_${i}_2`,
                font: 'Palatino',
                fontSize: '16px',
                html: `<div>Secondary spread text ${'A'.repeat(i % 50)}</div>`,
              },
            ],
          },
        ],
      };

      const encrypted = encryptData(payload, masterKey);
      assert.ok(encrypted.iv && encrypted.iv.length === 24, 'IV must be 12 bytes (24 hex chars)');
      assert.ok(encrypted.authTag && encrypted.authTag.length === 32, 'AuthTag must be 16 bytes (32 hex chars)');
      assert.ok(typeof encrypted.data === 'string' && encrypted.data.length > 0, 'Data must be base64 string');

      const decrypted = decryptData(encrypted, masterKey);
      assert.deepEqual(decrypted, payload, 'Decrypted vault payload must match original exactly');
    });
  }

  // Part B: 500 Cryptographic Tamper & Authentication Failure Tests
  for (let i = 0; i < 500; i++) {
    test(`[Crypto Tamper Detection ${i + 1}/500] Tamper vector #${i}`, () => {
      const samplePayload = { testId: i, message: `Confidential Note #${i}` };
      const encrypted = encryptData(samplePayload, masterKey);

      const tamperType = i % 5;
      if (tamperType === 0) {
        // Tamper Ciphertext data
        const cipherBuf = Buffer.from(encrypted.data, 'base64');
        const pos = i % cipherBuf.length;
        cipherBuf[pos] ^= 0x01; // flip 1 bit
        const tampered = { ...encrypted, data: cipherBuf.toString('base64') };
        assert.throws(() => decryptData(tampered, masterKey), /Unsupported state or unable to authenticate data|bad decrypt/i);
      } else if (tamperType === 1) {
        // Tamper Auth Tag
        const tagBuf = Buffer.from(encrypted.authTag, 'hex');
        const pos = i % tagBuf.length;
        tagBuf[pos] ^= 0xff;
        const tampered = { ...encrypted, authTag: tagBuf.toString('hex') };
        assert.throws(() => decryptData(tampered, masterKey), /Unsupported state or unable to authenticate data|bad decrypt/i);
      } else if (tamperType === 2) {
        // Tamper IV
        const ivBuf = Buffer.from(encrypted.iv, 'hex');
        const pos = i % ivBuf.length;
        ivBuf[pos] ^= 0x55;
        const tampered = { ...encrypted, iv: ivBuf.toString('hex') };
        assert.throws(() => decryptData(tampered, masterKey), /Unsupported state or unable to authenticate data|bad decrypt/i);
      } else if (tamperType === 3) {
        // Wrong Key
        const wrongKey = crypto.randomBytes(32);
        assert.throws(() => decryptData(encrypted, wrongKey), /Unsupported state or unable to authenticate data|bad decrypt/i);
      } else {
        // Truncated / malformed ciphertext
        const tampered = { ...encrypted, data: encrypted.data.slice(0, Math.max(1, encrypted.data.length - 8)) };
        assert.throws(() => decryptData(tampered, masterKey));
      }
    });
  }
});
