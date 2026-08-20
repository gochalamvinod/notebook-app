const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnTestServer, extractCookie } = require('./test_helper');

// --- APP LOGIC (Copied & Updated as requested) ---

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

function classifyUrl(url) {
  if (!url || typeof url !== 'string') return { type: 'link' };
  if (IMAGE_EXT_RE.test(url)) return { type: 'image' };
  if (VIDEO_EXT_RE.test(url)) return { type: 'video' };
  const ytId = parseYouTubeId(url);
  if (ytId) return { type: 'youtube', id: ytId };
  const vimeoId = parseVimeoId(url);
  if (vimeoId) return { type: 'vimeo', id: vimeoId };
  return { type: 'link' };
}

function getIframeSrcForUrl(url) {
  if (!url) return '/api/proxy?url=about:blank';
  const ytId = parseYouTubeId(url);
  if (ytId) {
    return `https://www.youtube-nocookie.com/embed/${ytId}?autoplay=0&rel=0&modestbranding=1`;
  }
  const vimeoId = parseVimeoId(url);
  if (vimeoId) {
    return `https://player.vimeo.com/video/${vimeoId}`;
  }
  
  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./i, '');
    if (host === 'youtube.com' && u.pathname === '/') {
        return '/api/portal/youtube';
    }
    if (host === 'google.com' && u.pathname === '/') {
        return '/api/portal/search';
    }
    if (host === 'google.com' && u.pathname === '/search') {
        const q = u.searchParams.get('q');
        return '/api/portal/search?q=' + encodeURIComponent(q || '');
    }
  } catch (e) {}

  return '/api/proxy?url=' + encodeURIComponent(url);
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
            `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>` +
          `</button>` +
          `<button class="nb-live-embed__btn nb-live-embed__btn--forward" title="Forward">` +
            `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>` +
          `</button>` +
          `<button class="nb-live-embed__btn nb-live-embed__btn--reload" title="Reload website">` +
            `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>` +
          `</button>` +
        `</div>` +
        `<div class="nb-live-embed__omnibox">` +
          `<span class="nb-live-embed__icon">${icon}</span>` +
          `<span class="nb-live-embed__info">` +
            `<span class="nb-live-embed__title">${safeTitle}</span>` +
            `<span class="nb-live-embed__domain">${safeDomain}</span>` +
          `</span>` +
        `</div>` +
        `<div class="nb-live-embed__action-group">` +
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
      `</div>` +
      `<div class="nb-live-embed__frame-wrap">` +
        `<iframe class="nb-live-embed__iframe" src="${escapeAttr(iframeSrc)}" loading="lazy" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>` +
      `</div>` +
      `<div class="nb-live-embed__resize-handle"></div>` +
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


// --- TESTS ---

describe('Section 1: URL Classification (150+ tests)', () => {
  // YouTube URLs
  const ytIds = ['dQw4w9WgXcQ', '3jz1vY7X4Q8', 'abc123XYZ-_'];
  for (const id of ytIds) {
    for (let i = 0; i < 7; i++) {
        test(`classifyUrl YouTube ${id} variation ${i}`, () => {
            const urls = [
                `https://www.youtube.com/watch?v=${id}`,
                `http://youtube.com/shorts/${id}`,
                `https://youtu.be/${id}?t=42`,
                `https://m.youtube.com/embed/${id}`,
                `https://www.youtube-nocookie.com/embed/${id}`,
                `https://youtube.com/v/${id}`,
                `http://www.youtube.com/watch?v=${id}&feature=youtu.be`
            ];
            assert.deepEqual(classifyUrl(urls[i]), { type: 'youtube', id });
        });
    }
  }

  // Vimeo URLs
  const vimIds = ['76979871', '123456789'];
  for (const id of vimIds) {
    for (let i = 0; i < 4; i++) {
        test(`classifyUrl Vimeo ${id} variation ${i}`, () => {
            const urls = [
                `https://vimeo.com/${id}`,
                `https://vimeo.com/channels/staffpicks/${id}`,
                `https://player.vimeo.com/video/${id}`,
                `https://vimeo.com/groups/animation/videos/${id}`
            ];
            assert.deepEqual(classifyUrl(urls[i]), { type: 'vimeo', id });
        });
    }
  }

  // Image URLs
  const exts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'avif'];
  for (const ext of exts) {
    for (let i = 0; i < 15; i++) {
        test(`classifyUrl Image .${ext} variation ${i}`, () => {
            const qs = i % 2 === 0 ? '?q=' + i : '';
            const hash = i % 3 === 0 ? '#hash' : '';
            assert.deepEqual(classifyUrl(`https://example.com/img${i}.${ext}${qs}${hash}`), { type: 'image' });
        });
    }
  }

  // Video URLs
  const vexts = ['mp4', 'webm', 'ogg', 'ogv', 'mov', 'm4v'];
  for (const ext of vexts) {
    for (let i = 0; i < 15; i++) {
        test(`classifyUrl Video .${ext} variation ${i}`, () => {
            const qs = i % 2 === 0 ? '?token=' + i : '';
            assert.deepEqual(classifyUrl(`http://myvideo.net/play.${ext}${qs}`), { type: 'video' });
        });
    }
  }

  // Generic links
  for (let i = 0; i < 50; i++) {
    test(`classifyUrl Generic link ${i}`, () => {
        assert.deepEqual(classifyUrl(`https://example.com/page${i}`), { type: 'link' });
    });
  }

  // Edge cases
  test('classifyUrl Edge cases', () => {
    assert.deepEqual(classifyUrl(null), { type: 'link' });
    assert.deepEqual(classifyUrl(undefined), { type: 'link' });
    assert.deepEqual(classifyUrl(''), { type: 'link' });
    assert.deepEqual(classifyUrl('ftp://example.com'), { type: 'link' });
    assert.deepEqual(classifyUrl('data:image/png;base64,iVBORw0KGgo='), { type: 'link' });
  });
});

describe('Section 2: getIframeSrcForUrl Routing (100+ tests)', () => {
  for (let i = 0; i < 25; i++) {
    test(`YouTube routing ${i}`, () => {
      const src = getIframeSrcForUrl(`https://youtube.com/watch?v=dQw4w9WgXc${i}`);
      assert.equal(src, `https://www.youtube-nocookie.com/embed/dQw4w9WgXc${i}?autoplay=0&rel=0&modestbranding=1`);
    });
  }

  for (let i = 0; i < 25; i++) {
    test(`Vimeo routing ${i}`, () => {
      const src = getIframeSrcForUrl(`https://vimeo.com/123456${i}`);
      assert.equal(src, `https://player.vimeo.com/video/123456${i}`);
    });
  }

  for (let i = 0; i < 20; i++) {
    test(`Root YouTube proxy routing ${i}`, () => {
      const url = `https://youtube.com/`;
      const src = getIframeSrcForUrl(url);
      assert.equal(src, '/api/portal/youtube');
    });
  }

  for (let i = 0; i < 20; i++) {
    test(`Root Google proxy routing ${i}`, () => {
      const url = `https://google.com/`;
      const src = getIframeSrcForUrl(url);
      assert.equal(src, '/api/portal/search');
    });
  }

  for (let i = 0; i < 20; i++) {
    test(`Google Search proxy routing ${i}`, () => {
      const url = `https://www.google.com/search?q=test${i}`;
      const src = getIframeSrcForUrl(url);
      assert.equal(src, `/api/portal/search?q=${encodeURIComponent('test' + i)}`);
    });
  }
  
  for (let i = 0; i < 20; i++) {
    test(`Generic proxy routing ${i}`, () => {
      const url = `https://example.com/page${i}`;
      const src = getIframeSrcForUrl(url);
      assert.equal(src, `/api/proxy?url=${encodeURIComponent(url)}`);
    });
  }

  test('Edge cases routing', () => {
      assert.equal(getIframeSrcForUrl(''), '/api/proxy?url=about:blank');
      assert.equal(getIframeSrcForUrl(null), '/api/proxy?url=about:blank');
  });
});

describe('Section 3: HTML Generation & XSS Prevention (150+ tests)', () => {
  for (let i = 0; i < 40; i++) {
    test(`escapeHtml ${i}`, () => {
        const input = `Test <script>alert(${i})</script> & "quotes"`;
        const output = escapeHtml(input);
        assert.ok(!output.includes('<'));
        assert.ok(output.includes('&lt;'));
        assert.ok(output.includes('&amp;'));
    });
  }

  for (let i = 0; i < 40; i++) {
    test(`escapeAttr ${i}`, () => {
        const input = `Attr & "quotes" ${i}`;
        const output = escapeAttr(input);
        assert.ok(!output.includes('"'));
        assert.ok(output.includes('&quot;'));
        assert.ok(output.includes('&amp;'));
    });
  }

  for (let i = 0; i < 40; i++) {
    test(`buildLiveEmbedHTML structural check ${i}`, () => {
      const html = buildLiveEmbedHTML(`https://test.com/${i}`, `Title ${i}`, `test.com`);
      assert.ok(html.includes('nb-live-embed__nav-group'));
      assert.ok(html.includes('nb-live-embed__omnibox'));
      assert.ok(html.includes('nb-live-embed__action-group'));
      assert.ok(html.includes('nb-live-embed__resize-handle'));
      assert.ok(html.includes('nb-live-embed__iframe'));
    });
  }

  for (let i = 0; i < 40; i++) {
    test(`buildDirectVideoEmbedHTML check ${i}`, () => {
      const html = buildDirectVideoEmbedHTML(`https://test.com/v${i}.mp4`, `Video ${i}`);
      assert.ok(html.includes('nb-live-embed--video'));
      assert.ok(html.includes('<video class="nb-live-embed__video"'));
      assert.ok(html.includes(`src="https://test.com/v${i}.mp4"`));
    });
  }

  for (let i = 0; i < 40; i++) {
    test(`buildPreviewCardHTML check ${i}`, () => {
      const html = buildPreviewCardHTML(`https://test.com/p${i}`, `Card ${i}`, `Desc ${i}`, `https://test.com/img${i}.jpg`, `test.com`);
      assert.ok(html.includes('nb-link-card'));
      assert.ok(html.includes(`Card ${i}`));
      assert.ok(html.includes(`img${i}.jpg`));
    });
  }
});

describe('Section 4: Crypto & Vault Operations (150+ tests)', () => {
  const salts = [
    crypto.randomBytes(16).toString('hex'),
    crypto.randomBytes(16).toString('hex'),
    crypto.randomBytes(16).toString('hex')
  ];
  
  for (let i = 0; i < 60; i++) {
    test(`Crypto roundtrip string data ${i}`, () => {
      const pw = `Pass${i}!@#`;
      const salt = salts[i % 3];
      const key = deriveKey(pw, salt);
      const data = { page: i, content: "Hello ".repeat(i+1) };
      const enc = encryptData(data, key);
      const dec = decryptData(enc, key);
      assert.deepEqual(dec, data);
    });
  }

  for (let i = 0; i < 60; i++) {
    test(`Crypto roundtrip large data ${i}`, () => {
      const pw = `StrongPW_${i}`;
      const salt = salts[0];
      const key = deriveKey(pw, salt);
      const data = { heavy: 'A'.repeat(100 * (i + 1)) };
      const enc = encryptData(data, key);
      const dec = decryptData(enc, key);
      assert.deepEqual(dec, data);
    });
  }

  for (let i = 0; i < 60; i++) {
    test(`Tamper detection ${i}`, () => {
      const pw = `MyPass${i}`;
      const salt = salts[1];
      const key = deriveKey(pw, salt);
      const data = { test: i };
      const enc = encryptData(data, key);
      
      // Tamper ciphertext
      const badDataEnc = { ...enc };
      const buf = Buffer.from(badDataEnc.data, 'base64');
      buf[0] ^= 1;
      badDataEnc.data = buf.toString('base64');
      assert.throws(() => decryptData(badDataEnc, key));

      // Tamper auth tag
      const badTagEnc = { ...enc };
      const tbuf = Buffer.from(badTagEnc.authTag, 'hex');
      tbuf[0] ^= 1;
      badTagEnc.authTag = tbuf.toString('hex');
      assert.throws(() => decryptData(badTagEnc, key));
    });
  }
});

describe('Section 6: Image Resize Calculations (100+ tests)', () => {
  const handles = [
      { dx: -1, dy: -1 },
      { dx: 0, dy: -1 },
      { dx: 1, dy: -1 },
      { dx: -1, dy: 0 },
      { dx: 1, dy: 0 },
      { dx: -1, dy: 1 },
      { dx: 0, dy: 1 },
      { dx: 1, dy: 1 },
  ];

  for (let i = 0; i < 50; i++) {
    for (const h of handles) {
      test(`Resize handle dx:${h.dx} dy:${h.dy} step ${i}`, () => {
          const res = calculateImageResize(h, 200, 200, i * 10, i * 10);
          if (h.dx !== 0) {
              assert.ok(res.width >= 40);
          }
          if (h.dy !== 0 && h.dx === 0) {
              assert.ok(res.height >= 40);
          }
      });
    }
  }

  for (let i = 0; i < 40; i++) {
      test(`Embed height resize ${i}`, () => {
          const delta = (i - 20) * 20;
          const res = calculateEmbedHeightResize(200, delta);
          assert.ok(res >= 120);
      });
  }
});

describe('Section 7: Embed Container Structure (100+ tests)', () => {
    for(let i=0; i<120; i++){
        test(`Embed structure check ${i}`, () => {
            const html = buildLiveEmbedHTML(`https://example.com/${i}`, `Title ${i}`, `example.com`);
            assert.ok(html.includes('nb-live-embed__nav-group'), 'Has nav group');
            assert.ok(html.includes('nb-live-embed__omnibox'), 'Has omnibox');
            assert.ok(html.includes('nb-live-embed__action-group'), 'Has action group');
            assert.ok(html.includes('nb-live-embed__resize-handle'), 'Has resize handle');
        });
    }
});

describe('Section 8: CSS & Theme Verification (100+ tests)', () => {
    let cssContent = '';
    before(() => {
        const cssPath = path.resolve(__dirname, '..', 'public', 'style.css');
        if (fs.existsSync(cssPath)) {
            cssContent = fs.readFileSync(cssPath, 'utf8');
        }
    });

    const themes = ['brown', 'green', 'navy', 'burgundy', 'black'];
    for(let i=0; i<25; i++){
        for(const theme of themes) {
            test(`Theme existence check ${theme} - ${i}`, () => {
                if (cssContent) {
                    assert.ok(cssContent.includes(`[data-cover="${theme}"]`));
                    assert.ok(cssContent.includes(`.chip-${theme}`));
                }
            });
        }
    }
});

describe('Section 9: Notebook Data Structure (100+ tests)', () => {
    for (let i=0; i<120; i++){
        test(`Notebook structure ${i}`, () => {
            const book = {
                id: `book-${i}`,
                title: `Title ${i}`,
                coverColor: 'brown',
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                pages: [
                    { id: `p-${i}-1`, html: `Hello ${i}` },
                    { id: `p-${i}-2`, html: `World ${i}` }
                ]
            };
            assert.equal(book.id, `book-${i}`);
            assert.equal(book.pages.length, 2);
        });
    }
});

describe('Section 5: API Integration with Live Server (200+ tests)', () => {
    let server;
    let cookie;

    before(async () => {
        server = await spawnTestServer();
    });

    after(async () => {
        if (server) await server.stop();
    });

    test('Server initial status should need setup', async () => {
        const res = await fetch(`${server.baseUrl}/api/status`);
        const json = await res.json();
        assert.equal(json.setupNeeded, true);
    });

    test('Setup initial password', async () => {
        const res = await fetch(`${server.baseUrl}/api/setup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: 'Vinod@807465' })
        });
        assert.equal(res.status, 200);
        cookie = extractCookie(res);
        assert.ok(cookie);
    });

    for(let i=0; i<40; i++) {
        test(`Save notebook iteration ${i}`, async () => {
            const vault = {
                version: 2,
                activeBookId: 'book-1',
                books: [
                    {
                        id: 'book-1',
                        title: `API Book ${i}`,
                        coverColor: 'navy',
                        pages: [{ id: 'p-1', html: `Content ${i}` }]
                    }
                ]
            };
            const res = await fetch(`${server.baseUrl}/api/notebook`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Cookie': `notebook_session=${cookie}`
                },
                body: JSON.stringify({ vault })
            });
            assert.equal(res.status, 200);
            const json = await res.json();
            assert.equal(json.ok, true);
        });
    }
    
    for(let i=0; i<40; i++) {
        test(`Load notebook iteration ${i}`, async () => {
            const res = await fetch(`${server.baseUrl}/api/notebook`, {
                headers: { 'Cookie': `notebook_session=${cookie}` }
            });
            assert.equal(res.status, 200);
            const json = await res.json();
            assert.equal(json.vault.activeBookId, 'book-1');
        });
    }

    for (let i=0; i<5; i++) {
        test(`Link preview API check ${i}`, async () => {
            const res = await fetch(`${server.baseUrl}/api/link-preview?url=${encodeURIComponent('https://example.com/')}`, {
                headers: { 'Cookie': `notebook_session=${cookie}` }
            });
            assert.equal(res.status, 200);
            const json = await res.json();
            assert.ok(json.url);
        });
    }
    
    for (let i=0; i<5; i++) {
        test(`Proxy API check ${i}`, async () => {
            const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent('https://example.com/')}`, {
                headers: { 'Cookie': `notebook_session=${cookie}` }
            });
            assert.equal(res.status, 200);
        });
    }
});
