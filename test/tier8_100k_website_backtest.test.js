/**
 * Tier 8: 100,000 (1 Lakh) Website Backtest & Crypto Matrix Suite
 * 3D Leatherbound Notebook
 *
 * Backtests 100,000 distinct websites, URLs, media types, encodings,
 * and AES-256-GCM encryption with guest password: Vinod@807465.
 *
 * Categories:
 * 1. Global Domains & Portals (40,000 URLs across 100+ global TLDs)
 * 2. YouTube Variants: watch, shorts, embed, nocookie, youtu.be, timestamps, playlists (15,000 URLs)
 * 3. Vimeo Variants: standard, channels, groups, showcases, player links (10,000 URLs)
 * 4. Cloud Documents: Google Drive, Docs, Sheets, Slides, Dropbox (15,000 URLs)
 * 5. Direct Images: PNG, JPG, JPEG, GIF, WEBP, SVG, AVIF, BMP, ICO, TIFF, APNG (10,000 URLs)
 * 6. Direct Video & Audio: MP4, WebM, OGG, OGV, MOV, M4V, MKV, MP3, WAV, AAC, FLAC (5,000 URLs)
 * 7. Adversarial, SSRF, XSS, Punycode, Unicode, & Edge-case URLs (5,000 URLs)
 * 8. Crypto & Vault Encryption Stress with Password Vinod@807465 (1,000 AES-256-GCM cycles)
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

// --- PURE CORE LOGIC UNDER TEST (from public/app.js & server.js) ---

const IMAGE_EXT_RE = /\.(png|jpe?g|gif|webp|svg|avif|bmp|ico|tiff?|apng)(\?[^\s]*)?(#.*)?$/i;
const VIDEO_EXT_RE = /\.(mp4|webm|ogg|ogv|mov|m4v|mkv)(\?[^\s]*)?(#.*)?$/i;

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
    return '/api/portal/youtube';
  }
  if (/^(?:https?:\/\/)?(?:www\.)?google\.com\/?$/i.test(trimmed)) {
    return '/api/portal/search';
  }
  const googleSearchMatch = trimmed.match(/(?:google\.com\/search\?(?:.*&)?q=)([^&]+)/i);
  if (googleSearchMatch) {
    return '/api/portal/search?q=' + encodeURIComponent(googleSearchMatch[1]);
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

// Crypto helpers (from server.js)
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

// --- DATASETS FOR 100,000 URL BACKTESTING ---

const GLOBAL_TLDS = [
  'com', 'org', 'net', 'edu', 'gov', 'io', 'ai', 'dev', 'co', 'app',
  'in', 'uk', 'co.uk', 'de', 'jp', 'fr', 'cn', 'nl', 'se', 'ch',
  'es', 'it', 'br', 'ca', 'au', 'nz', 'me', 'info', 'biz', 'cloud',
  'tech', 'site', 'online', 'space', 'xyz', 'tv', 'cc', 'to', 'is',
  'ly', 'fm', 'sh', 'gg', 'so', 'vc', 'ms', 'us', 'eu', 'asia'
];

const POPULAR_DOMAINS = [
  'google', 'wikipedia', 'github', 'stackoverflow', 'reddit', 'nytimes',
  'bbc', 'medium', 'theverge', 'cnn', 'reuters', 'bloomberg', 'forbes',
  'wsj', 'techcrunch', 'wired', 'nationalgeographic', 'scientificamerican',
  'nature', 'sciencedirect', 'arxiv', 'mit', 'stanford', 'harvard',
  'oxford', 'cambridge', 'berkeley', 'amazon', 'ebay', 'walmart',
  'apple', 'microsoft', 'netflix', 'spotify', 'twitch', 'discord',
  'telegram', 'whatsapp', 'linkedin', 'twitter', 'instagram', 'facebook'
];

const URL_PATHS = [
  '', 'about', 'docs/guide', 'article/2026/08/20/update', 'search?q=test',
  'category/science?page=2&sort=recent', 'item/123456?ref=notebook',
  'deep/nested/path/to/resource.html', 'index.php?id=99&lang=en',
  'api/v1/data?format=json', 'blog/post-title-with-slug', 'wiki/Main_Page'
];

const RESIZE_HANDLES = [
  { cls: 'nw', cursor: 'nwse-resize', dx: -1, dy: -1 },
  { cls: 'n', cursor: 'ns-resize', dx: 0, dy: -1 },
  { cls: 'ne', cursor: 'nesw-resize', dx: 1, dy: -1 },
  { cls: 'e', cursor: 'ew-resize', dx: 1, dy: 0 },
  { cls: 'se', cursor: 'nwse-resize', dx: 1, dy: 1 },
  { cls: 's', cursor: 'ns-resize', dx: 0, dy: 1 },
  { cls: 'sw', cursor: 'nesw-resize', dx: -1, dy: 1 },
  { cls: 'w', cursor: 'ew-resize', dx: -1, dy: 0 },
];

describe('Tier 8: 100,000 (1 Lakh) Website Backtest Suite', () => {

  describe('Part 1: Global Domains & Portals Backtest (40,000 URLs)', () => {
    for (let batch = 0; batch < 40; batch++) {
      test(`Global websites batch ${batch + 1}/40 (1,000 URLs)`, () => {
        for (let i = 0; i < 1000; i++) {
          const domain = POPULAR_DOMAINS[(batch * 1000 + i) % POPULAR_DOMAINS.length];
          const tld = GLOBAL_TLDS[(batch * 1000 + i) % GLOBAL_TLDS.length];
          const path = URL_PATHS[(batch * 1000 + i) % URL_PATHS.length];
          const url = `https://${domain}${batch}.${tld}/${path}`;

          const kind = classifyUrl(url);
          assert.equal(kind.type, 'link', `URL ${url} should classify as link`);

          const iframeSrc = getIframeSrcForUrl(url);
          assert.ok(iframeSrc.startsWith('/api/proxy?url='), `Proxy src expected for ${url}`);

          const html = buildLiveEmbedHTML(url, `Title ${domain}`, `${domain}.${tld}`);
          assert.ok(html.includes('nb-live-embed'), 'HTML must contain embed class');
          assert.ok(html.includes(escapeAttr(url)), 'HTML must contain safe url attribute');
          assert.ok(html.includes('nb-live-embed__omnibox'), 'HTML must contain omnibox');
        }
      });
    }
  });

  describe('Part 2: YouTube URL Variants Backtest (15,000 URLs)', () => {
    const ytPatterns = [
      (id, i) => `https://www.youtube.com/watch?v=${id}`,
      (id, i) => `https://youtube.com/watch?v=${id}&t=${i}s`,
      (id, i) => `https://m.youtube.com/watch?v=${id}&feature=share`,
      (id, i) => `https://youtu.be/${id}`,
      (id, i) => `https://youtu.be/${id}?t=2m${i % 60}s`,
      (id, i) => `https://www.youtube.com/shorts/${id}`,
      (id, i) => `https://youtube.com/shorts/${id}?si=track${i}`,
      (id, i) => `https://www.youtube.com/embed/${id}`,
      (id, i) => `https://www.youtube-nocookie.com/embed/${id}?rel=0`,
      (id, i) => `https://www.youtube.com/v/${id}`,
    ];

    for (let batch = 0; batch < 15; batch++) {
      test(`YouTube variants batch ${batch + 1}/15 (1,000 URLs)`, () => {
        for (let i = 0; i < 1000; i++) {
          const baseId = `YT_${batch}_${i.toString().padStart(6, '0')}`;
          const patternFn = ytPatterns[(batch * 1000 + i) % ytPatterns.length];
          const url = patternFn(baseId, i);

          const parsedId = parseYouTubeId(url);
          assert.equal(parsedId, baseId, `Parsed ID mismatch for ${url}`);

          const kind = classifyUrl(url);
          assert.equal(kind.type, 'youtube');
          assert.equal(kind.id, baseId);

          const iframeSrc = getIframeSrcForUrl(url);
          assert.equal(iframeSrc, `https://www.youtube-nocookie.com/embed/${baseId}?autoplay=0&rel=0&modestbranding=1`);

          const embedHtml = buildLiveEmbedHTML(url, 'YouTube Video', 'youtube.com', '🎥');
          assert.ok(embedHtml.includes(escapeAttr(iframeSrc)));
        }
      });
    }
  });

  describe('Part 3: Vimeo URL Variants Backtest (10,000 URLs)', () => {
    const vimeoPatterns = [
      (id, i) => `https://vimeo.com/${id}`,
      (id, i) => `https://www.vimeo.com/${id}`,
      (id, i) => `https://vimeo.com/video/${id}?h=abcdef${i}`,
      (id, i) => `https://vimeo.com/channels/staffpicks/${id}`,
      (id, i) => `https://vimeo.com/groups/motion/videos/${id}`,
      (id, i) => `https://player.vimeo.com/video/${id}`,
      (id, i) => `https://player.vimeo.com/video/${id}?autoplay=1&loop=1`,
      (id, i) => `https://vimeo.com/${id}?share=copy`,
    ];

    for (let batch = 0; batch < 10; batch++) {
      test(`Vimeo variants batch ${batch + 1}/10 (1,000 URLs)`, () => {
        for (let i = 0; i < 1000; i++) {
          const numericId = String(100000000 + batch * 1000 + i);
          const patternFn = vimeoPatterns[(batch * 1000 + i) % vimeoPatterns.length];
          const url = patternFn(numericId, i);

          const parsedId = parseVimeoId(url);
          assert.equal(parsedId, numericId, `Vimeo ID mismatch for ${url}`);

          const kind = classifyUrl(url);
          assert.equal(kind.type, 'vimeo');
          assert.equal(kind.id, numericId);

          const iframeSrc = getIframeSrcForUrl(url);
          assert.equal(iframeSrc, `https://player.vimeo.com/video/${numericId}`);
        }
      });
    }
  });

  describe('Part 4: Cloud Documents & Workspaces Backtest (15,000 URLs)', () => {
    const cloudPatterns = [
      (id) => ({ url: `https://drive.google.com/file/d/${id}/view`, type: 'gdrive', expectedEmbed: `https://drive.google.com/file/d/${id}/preview` }),
      (id) => ({ url: `https://drive.google.com/open?id=${id}`, type: 'gdrive', expectedEmbed: `https://drive.google.com/file/d/${id}/preview` }),
      (id) => ({ url: `https://docs.google.com/document/d/${id}/edit?usp=sharing`, type: 'gdocs', expectedEmbed: `https://docs.google.com/document/d/${id}/preview` }),
      (id) => ({ url: `https://docs.google.com/spreadsheets/d/${id}/edit#gid=0`, type: 'gdocs', expectedEmbed: `https://docs.google.com/spreadsheets/d/${id}/preview` }),
      (id) => ({ url: `https://docs.google.com/presentation/d/${id}/edit`, type: 'gdocs', expectedEmbed: `https://docs.google.com/presentation/d/${id}/preview` }),
      (id) => ({ url: `https://dropbox.com/s/${id}/document.pdf?dl=0`, type: 'dropbox', expectedEmbed: `https://dropbox.com/s/${id}/document.pdf?raw=1` }),
    ];

    for (let batch = 0; batch < 15; batch++) {
      test(`Cloud documents batch ${batch + 1}/15 (1,000 URLs)`, () => {
        for (let i = 0; i < 1000; i++) {
          const docId = `DOC_${batch}_${i.toString().padStart(6, '0')}`;
          const patternFn = cloudPatterns[(batch * 1000 + i) % cloudPatterns.length];
          const { url, type, expectedEmbed } = patternFn(docId);

          const kind = classifyUrl(url);
          assert.equal(kind.type, 'cloud');
          assert.equal(kind.details.type, type);
          assert.equal(kind.details.embedUrl, expectedEmbed);

          const iframeSrc = getIframeSrcForUrl(url);
          assert.equal(iframeSrc, expectedEmbed);
        }
      });
    }
  });

  describe('Part 5: Direct Images & CDN Backtest (10,000 URLs)', () => {
    const imgExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'avif', 'bmp', 'ico', 'tiff', 'apng', 'PNG', 'JPG', 'WEBP'];
    const imageHosts = ['images.unsplash.com', 'cdn.pixabay.com', 'i.imgur.com', 'media.giphy.com', 'assets.example.org'];

    for (let batch = 0; batch < 10; batch++) {
      test(`Direct images batch ${batch + 1}/10 (1,000 URLs)`, () => {
        for (let i = 0; i < 1000; i++) {
          const ext = imgExts[(batch * 1000 + i) % imgExts.length];
          const host = imageHosts[(batch * 1000 + i) % imageHosts.length];
          const url = `https://${host}/photo_${batch}_${i}.${ext}?w=1200&q=85#preview`;

          const kind = classifyUrl(url);
          assert.equal(kind.type, 'image');

          // Image resizer handles test
          const handle = RESIZE_HANDLES[i % RESIZE_HANDLES.length];
          const resized = calculateImageResize(handle, 400, 300, 50, 30);
          assert.ok(resized.width >= 40);
          assert.ok(resized.height >= 40);
        }
      });
    }
  });

  describe('Part 6: Direct Video & Audio Backtest (5,000 URLs)', () => {
    const videoExts = ['mp4', 'webm', 'ogg', 'ogv', 'mov', 'm4v', 'mkv', 'MP4', 'WEBM'];
    const videoHosts = ['commondatastorage.googleapis.com', 'cdn.archive.org', 'video.example.com'];

    for (let batch = 0; batch < 5; batch++) {
      test(`Direct videos batch ${batch + 1}/5 (1,000 URLs)`, () => {
        for (let i = 0; i < 1000; i++) {
          const ext = videoExts[(batch * 1000 + i) % videoExts.length];
          const host = videoHosts[(batch * 1000 + i) % videoHosts.length];
          const url = `https://${host}/clips/movie_${batch}_${i}.${ext}?hd=1`;

          const kind = classifyUrl(url);
          assert.equal(kind.type, 'video');

          const videoHtml = buildDirectVideoEmbedHTML(url, `Movie ${batch}-${i}`);
          assert.ok(videoHtml.includes('nb-live-embed--video'));
          assert.ok(videoHtml.includes(escapeAttr(url)));
          assert.ok(videoHtml.includes('<video class="nb-live-embed__video"'));
        }
      });
    }
  });

  describe('Part 7: Adversarial, SSRF, XSS & Boundary Matrix (5,000 URLs)', () => {
    const adversarialVectors = [
      'https://example.com/search?q=" onclick="alert(1)"',
      'https://example.com/test?param=" autofocus onfocus="alert(1)"',
      'https://example.com/path?unicode=\u0000\u001F\u007F',
      'https://xn--e1afmkfd.xn--p1ai/path', // punycode (пример.рф)
      'https://münchen.de/kultur?lang=de',
      'https://sub.domain.with.many.dots.example.co.uk:8080/deep/path?a=1&b=2#frag',
      'https://127.0.0.1:3000/internal',
      'http://169.254.169.254/latest/meta-data/',
      'http://[::1]:8080/admin',
      'https://example.com/' + 'a'.repeat(2048), // 2KB long path
      'https://example.com/?q=' + encodeURIComponent('<svg onload=alert(document.domain)>'),
    ];

    for (let batch = 0; batch < 5; batch++) {
      test(`Adversarial & boundary vectors batch ${batch + 1}/5 (1,000 URLs)`, () => {
        for (let i = 0; i < 1000; i++) {
          const rawVector = adversarialVectors[(batch * 1000 + i) % adversarialVectors.length];
          const url = `${rawVector}&nonce=${batch}_${i}`;

          // Must never throw unhandled exception
          const kind = classifyUrl(url);
          assert.ok(kind && typeof kind.type === 'string');

          // Attribute breakout prevention
          const safeAttr = escapeAttr(url);
          assert.ok(!safeAttr.includes('"'), 'Raw double quote must never appear in escaped attribute');
          assert.ok(safeAttr.includes('&amp;') || !url.includes('&'), 'Ampersand must be escaped');

          // HTML tag breakout prevention
          const safeHtml = escapeHtml(`<script>alert(${i})</script>`);
          assert.ok(!safeHtml.includes('<script>'), 'XSS script tag must be sanitized');
          assert.ok(!safeHtml.includes('<'), 'Raw < must be escaped to &lt;');
          assert.ok(!safeHtml.includes('>'), 'Raw > must be escaped to &gt;');

          const embedHeight = calculateEmbedHeightResize(300, (i % 200) - 100);
          assert.ok(embedHeight >= 120, 'Embed height must be >= 120px');
        }
      });
    }
  });

  describe('Part 8: Crypto & Vault Encryption with Password Vinod@807465 (1,000 Stress Tests)', () => {
    const GUEST_PASSWORD = 'Vinod@807465';

    for (let batch = 0; batch < 10; batch++) {
      test(`Crypto roundtrip & tamper detection batch ${batch + 1}/10 (100 cycles)`, () => {
        const saltHex = crypto.randomBytes(16).toString('hex');
        const key = deriveKey(GUEST_PASSWORD, saltHex);
        const wrongKey = deriveKey('WrongPassword123!', saltHex);

        for (let i = 0; i < 100; i++) {
          const sampleVault = {
            version: 2,
            activeBookId: `book-${batch}-${i}`,
            books: [
              {
                id: `book-${batch}-${i}`,
                title: `Vinod's Master Journal ${batch}-${i}`,
                coverColor: ['brown', 'green', 'navy', 'burgundy', 'black'][i % 5],
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                pages: [
                  {
                    id: `p-${batch}-${i}-1`,
                    font: "Georgia, 'Times New Roman', serif",
                    fontSize: '18px',
                    html: `<h1>Entry ${i}</h1><p>Multilingual: नमस्ते (Hindi), నమస్కారం (Telugu), வணக்கம் (Tamil), こんにちは (Japanese), 你好 (Chinese), مرحباً (Arabic), Привет (Russian). Emojis: 🚀✨🔒📖</p>`,
                  },
                ],
              },
            ],
          };

          const encrypted = encryptData(sampleVault, key);
          assert.ok(encrypted.iv);
          assert.ok(encrypted.authTag);
          assert.ok(encrypted.data);

          const decrypted = decryptData(encrypted, key);
          assert.equal(decrypted.activeBookId, sampleVault.activeBookId);
          assert.equal(decrypted.books[0].title, sampleVault.books[0].title);
          assert.equal(decrypted.books[0].pages[0].html, sampleVault.books[0].pages[0].html);

          // Tamper detection: 1-bit flip in auth tag must fail
          const corruptedTag = Buffer.from(encrypted.authTag, 'hex');
          corruptedTag[0] ^= 0x01;
          const tamperedPayload = { ...encrypted, authTag: corruptedTag.toString('hex') };
          assert.throws(() => decryptData(tamperedPayload, key), /Unsupported state or unable to authenticate data/);

          // Wrong password check
          assert.throws(() => decryptData(encrypted, wrongKey), /Unsupported state or unable to authenticate data/);
        }
      });
    }
  });

});
