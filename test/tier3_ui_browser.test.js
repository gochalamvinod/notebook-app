const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Reference client URL classification and transformation logic (from public/app.js)
const BARE_URL_RE = /^https?:\/\/\S+$/i;
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
  return '/api/proxy?url=' + encodeURIComponent(url);
}

function escapeHtml(s) {
  return (s || '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function escapeAttr(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

function buildLiveEmbedHTML(url, title, domain, icon = '🌐') {
  const safeUrl = escapeAttr(url);
  const safeTitle = escapeHtml((title || url).slice(0, 120));
  const safeDomain = escapeHtml(domain || '');
  const iframeSrc = getIframeSrcForUrl(url);

  return (
    `<div class="nb-live-embed" contenteditable="false" data-url="${safeUrl}">` +
      `<div class="nb-live-embed__bar">` +
        `<span class="nb-live-embed__icon">${icon}</span>` +
        `<span class="nb-live-embed__info">` +
          `<span class="nb-live-embed__title">${safeTitle}</span>` +
          `<span class="nb-live-embed__domain">${safeDomain}</span>` +
        `</span>` +
        `<button class="nb-live-embed__btn nb-live-embed__btn--reload" title="Reload website">` +
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
        `<iframe class="nb-live-embed__iframe" src="${escapeAttr(iframeSrc)}" loading="lazy" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>` +
      `</div>` +
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

// 8-handle image resize calculation helper matching app.js
function calculateImageResize(handle, startW, startH, deltaX, deltaY) {
  let w = startW;
  let h = startH;

  if (handle.dx !== 0) {
    w = Math.max(40, startW + handle.dx * deltaX);
  }
  if (handle.dy !== 0 && handle.dx === 0) {
    // Pure vertical drag (N / S): height changes, width remains auto
    h = Math.max(40, startH + handle.dy * deltaY);
  }
  return { width: w, height: h };
}

// Height resize calculation helper matching app.js
function calculateEmbedHeightResize(startH, deltaY) {
  return Math.max(120, startH + deltaY);
}

describe('Tier 3: UI & Browser Logic Tests', () => {

  describe('YouTube Video URL Parsing & Transformation', () => {
    test('parses standard youtube.com/watch?v=VIDEO_ID format', () => {
      const url = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
      const id = parseYouTubeId(url);
      assert.equal(id, 'dQw4w9WgXcQ');
      assert.equal(classifyUrl(url).type, 'youtube');
      assert.equal(
        getIframeSrcForUrl(url),
        'https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ?autoplay=0&rel=0&modestbranding=1'
      );
    });

    test('parses youtube.com/shorts/VIDEO_ID format', () => {
      const url = 'https://www.youtube.com/shorts/3jz1vY7X4Q8';
      const id = parseYouTubeId(url);
      assert.equal(id, '3jz1vY7X4Q8');
      assert.equal(
        getIframeSrcForUrl(url),
        'https://www.youtube-nocookie.com/embed/3jz1vY7X4Q8?autoplay=0&rel=0&modestbranding=1'
      );
    });

    test('parses youtu.be/VIDEO_ID shortened format', () => {
      const url = 'https://youtu.be/9bZkp7q19f0?t=42s';
      const id = parseYouTubeId(url);
      assert.equal(id, '9bZkp7q19f0');
      assert.equal(
        getIframeSrcForUrl(url),
        'https://www.youtube-nocookie.com/embed/9bZkp7q19f0?autoplay=0&rel=0&modestbranding=1'
      );
    });

    test('parses mobile m.youtube.com and embed paths', () => {
      const mobileUrl = 'https://m.youtube.com/watch?v=kffacxfA7G4&feature=shared';
      assert.equal(parseYouTubeId(mobileUrl), 'kffacxfA7G4');

      const embedUrl = 'https://www.youtube.com/embed/kffacxfA7G4';
      assert.equal(parseYouTubeId(embedUrl), 'kffacxfA7G4');

      const nocookieUrl = 'https://www.youtube-nocookie.com/embed/kffacxfA7G4';
      assert.equal(parseYouTubeId(nocookieUrl), 'kffacxfA7G4');
    });

    test('verifies YouTube embeds NEVER route through /api/proxy (prevents STATUS_BREAKPOINT crashes)', () => {
      const ytUrl = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
      const iframeSrc = getIframeSrcForUrl(ytUrl);
      assert.ok(!iframeSrc.includes('/api/proxy'), 'YouTube URL must never be wrapped in proxy');
      assert.ok(iframeSrc.startsWith('https://www.youtube-nocookie.com/embed/'));
    });
  });

  describe('Vimeo & Video Embed Parsing', () => {
    test('parses direct vimeo.com/VIDEO_ID format', () => {
      const url = 'https://vimeo.com/76979871';
      const id = parseVimeoId(url);
      assert.equal(id, '76979871');
      assert.equal(classifyUrl(url).type, 'vimeo');
      assert.equal(getIframeSrcForUrl(url), 'https://player.vimeo.com/video/76979871');
    });

    test('parses vimeo channels and groups paths', () => {
      const channelUrl = 'https://vimeo.com/channels/staffpicks/987654321';
      assert.equal(parseVimeoId(channelUrl), '987654321');

      const playerUrl = 'https://player.vimeo.com/video/987654321';
      assert.equal(parseVimeoId(playerUrl), '987654321');
    });

    test('classifies direct HTML5 video file URLs (.mp4, .webm, .ogg, .mov, .m4v)', () => {
      const mp4Url = 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4';
      assert.equal(classifyUrl(mp4Url).type, 'video');

      const webmUrl = 'https://example.com/assets/clip.webm?token=123#t=10';
      assert.equal(classifyUrl(webmUrl).type, 'video');

      const movUrl = 'https://example.com/video.mov';
      assert.equal(classifyUrl(movUrl).type, 'video');
    });

    test('generates HTML5 video container with native controls and playsinline attributes', () => {
      const videoUrl = 'https://example.com/demo.mp4';
      const html = buildDirectVideoEmbedHTML(videoUrl, 'Sample Clip');
      assert.ok(html.includes('class="nb-live-embed nb-live-embed--video"'));
      assert.ok(html.includes('<video class="nb-live-embed__video" src="https://example.com/demo.mp4" controls preload="metadata" playsinline></video>'));
      assert.ok(html.includes('Sample Clip'));
      assert.ok(html.includes('HTML5 Video'));
    });
  });

  describe('Generic Website Live Embeds & Header Controls', () => {
    test('routes generic website URLs through /api/proxy', () => {
      const url = 'https://en.wikipedia.org/wiki/Leather';
      assert.equal(classifyUrl(url).type, 'link');
      const iframeSrc = getIframeSrcForUrl(url);
      assert.equal(iframeSrc, '/api/proxy?url=' + encodeURIComponent(url));
    });

    test('constructs live embed container containing all 5 header bar controls', () => {
      const url = 'https://tradingview.com';
      const html = buildLiveEmbedHTML(url, 'TradingView Chart', 'tradingview.com', '📈');

      assert.ok(html.includes('class="nb-live-embed"'));
      assert.ok(html.includes('data-url="https://tradingview.com"'));
      assert.ok(html.includes('class="nb-live-embed__title">TradingView Chart</span>'));
      assert.ok(html.includes('class="nb-live-embed__domain">tradingview.com</span>'));

      // 1. Reload button
      assert.ok(html.includes('nb-live-embed__btn--reload'));
      // 2. Expand/Fullscreen button
      assert.ok(html.includes('nb-live-embed__btn--expand'));
      // 3. Open in new tab link
      assert.ok(html.includes('nb-live-embed__btn--open'));
      assert.ok(html.includes('href="https://tradingview.com"'));
      assert.ok(html.includes('target="_blank"'));
      // 4. Remove button
      assert.ok(html.includes('nb-live-embed__btn--remove'));
      // 5. Iframe with lazy loading and permissions
      assert.ok(html.includes('<iframe class="nb-live-embed__iframe"'));
      assert.ok(html.includes('allowfullscreen'));
    });

    test('escapes malicious HTML attributes and text in embed URLs and titles', () => {
      const maliciousUrl = 'https://example.com/page?x=" onload="alert(1)';
      const maliciousTitle = '<img src=x onerror=alert(1)> Vulnerability';
      const html = buildLiveEmbedHTML(maliciousUrl, maliciousTitle, 'example.com');

      // Title is properly HTML entity encoded
      assert.ok(!html.includes('<img src=x'));
      assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
      // Attribute quotes are properly escaped to prevent attribute breakout
      assert.ok(!html.includes('x=" onload="'));
      assert.ok(html.includes('&quot; onload=&quot;'));
    });
  });

  describe('5 Leather Cover Themes & Visual Styling', () => {
    const cssPath = path.resolve(__dirname, '..', 'public', 'style.css');
    let cssContent = '';

    test('verifies all 5 leather cover themes exist in style.css', () => {
      cssContent = fs.readFileSync(cssPath, 'utf8');

      const expectedThemes = ['brown', 'green', 'navy', 'burgundy', 'black'];
      for (const theme of expectedThemes) {
        assert.ok(
          cssContent.includes(`[data-cover="${theme}"]`),
          `Theme [data-cover="${theme}"] must be defined in style.css`
        );
        assert.ok(
          cssContent.includes(`.chip-${theme}`),
          `Palette chip .chip-${theme} must be defined in style.css`
        );
        assert.ok(
          cssContent.includes(`.spine-${theme}`),
          `Book spine .spine-${theme} must be defined in style.css`
        );
      }
    });

    test('verifies Classic Brown theme color variables', () => {
      assert.ok(cssContent.includes('[data-cover="brown"]'));
      assert.ok(cssContent.includes('--cover-dark: #2b170c'));
      assert.ok(cssContent.includes('--cover-mid: #3d2314'));
      assert.ok(cssContent.includes('.chip-brown { background: #3d2314; }'));
    });

    test('verifies Emerald Pine theme color variables', () => {
      assert.ok(cssContent.includes('[data-cover="green"]'));
      assert.ok(cssContent.includes('--cover-dark: #16281f'));
      assert.ok(cssContent.includes('--cover-mid: #1f3b32'));
      assert.ok(cssContent.includes('.chip-green { background: #16281f; }'));
    });

    test('verifies Midnight Navy theme color variables', () => {
      assert.ok(cssContent.includes('[data-cover="navy"]'));
      assert.ok(cssContent.includes('--cover-dark: #0d1522'));
      assert.ok(cssContent.includes('--cover-mid: #121c2b'));
      assert.ok(cssContent.includes('.chip-navy { background: #121c2b; }'));
    });

    test('verifies Royal Burgundy theme color variables', () => {
      assert.ok(cssContent.includes('[data-cover="burgundy"]'));
      assert.ok(cssContent.includes('--cover-dark: #240b11'));
      assert.ok(cssContent.includes('--cover-mid: #3b141d'));
      assert.ok(cssContent.includes('.chip-burgundy { background: #3b141d; }'));
    });

    test('verifies Obsidian Noir theme color variables', () => {
      assert.ok(cssContent.includes('[data-cover="black"]'));
      assert.ok(cssContent.includes('--cover-dark: #0f0f0f'));
      assert.ok(cssContent.includes('--cover-mid: #1a1a1a'));
      assert.ok(cssContent.includes('.chip-black { background: #1a1a1a; }'));
    });
  });

  describe('8-Handle Image Resize Calculations & Aspect Ratio Preservation', () => {
    const handles = {
      nw: { cls: 'nw', cursor: 'nw-resize', dx: -1, dy: -1 },
      n:  { cls: 'n',  cursor: 'n-resize',  dx:  0, dy: -1 },
      ne: { cls: 'ne', cursor: 'ne-resize', dx:  1, dy: -1 },
      w:  { cls: 'w',  cursor: 'w-resize',  dx: -1, dy:  0 },
      e:  { cls: 'e',  cursor: 'e-resize',  dx:  1, dy:  0 },
      sw: { cls: 'sw', cursor: 'sw-resize', dx: -1, dy:  1 },
      s:  { cls: 's',  cursor: 's-resize',  dx:  0, dy:  1 },
      se: { cls: 'se', cursor: 'se-resize', dx:  1, dy:  1 },
    };

    test('East (E) handle expands width proportionally and leaves height auto', () => {
      const result = calculateImageResize(handles.e, 200, 150, 50, 0);
      assert.equal(result.width, 250);
      assert.equal(result.height, 150);
    });

    test('West (W) handle shrinks width with positive deltaX and enforces min-width clamp', () => {
      const result = calculateImageResize(handles.w, 200, 150, 50, 0);
      assert.equal(result.width, 150);

      // Extreme drag beyond minimum width clamp (40px)
      const clamped = calculateImageResize(handles.w, 200, 150, 300, 0);
      assert.equal(clamped.width, 40);
    });

    test('South (S) handle expands height for pure vertical resizing', () => {
      const result = calculateImageResize(handles.s, 200, 150, 0, 40);
      assert.equal(result.width, 200);
      assert.equal(result.height, 190);
    });

    test('North (N) handle shrinks height and enforces min-height clamp (40px)', () => {
      const result = calculateImageResize(handles.n, 200, 150, 0, 30);
      assert.equal(result.height, 120);

      const clamped = calculateImageResize(handles.n, 200, 150, 0, 200);
      assert.equal(clamped.height, 40);
    });

    test('Corner Southeast (SE) handle updates width correctly', () => {
      const result = calculateImageResize(handles.se, 300, 200, 60, 40);
      assert.equal(result.width, 360);
    });

    test('Embed container height resize calculates and enforces min-height (120px)', () => {
      const normalResize = calculateEmbedHeightResize(300, 50);
      assert.equal(normalResize, 350);

      const clampedResize = calculateEmbedHeightResize(300, -250);
      assert.equal(clampedResize, 120);
    });
  });

});
