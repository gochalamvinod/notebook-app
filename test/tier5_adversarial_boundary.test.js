/**
 * Tier 5: Adversarial Boundary & White-Box Code Coverage Test Suite
 * 3D Leatherbound Notebook
 *
 * Tests 5 critical adversarial boundary areas:
 * 1. Proxy error handling (DNS failures, socket timeouts, HTTP 500 upstreams, redirect loops > 8).
 * 2. Edge cases in YouTube URL parsing (query params, timestamps, playlists, malformed IDs).
 * 3. Edge cases in 8-handle image resizing (negative coordinates, extreme drag deltas, zero dimensions).
 * 4. Bookshelf drawer edge cases (deleting active book, deleting when 1 book exists, switching to nonexistent IDs).
 * 5. Session cookie boundary tests (SameSite=None; Secure on HTTPS vs SameSite=Lax on HTTP, token corruption).
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { spawnTestServer, extractCookie, getFreePort, createSandbox } = require('./test_helper.js');

// ---------------------------------------------------------------------------
// Client Logic Mirrors (from public/app.js) for White-Box Stress Testing
// ---------------------------------------------------------------------------

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

function calculateHandleResize(handleType, startW, startH, deltaX, deltaY) {
  const HANDLES = {
    nw: { dx: -1, dy: -1 },
    n:  { dx:  0, dy: -1 },
    ne: { dx:  1, dy: -1 },
    w:  { dx: -1, dy:  0 },
    e:  { dx:  1, dy:  0 },
    sw: { dx: -1, dy:  1 },
    s:  { dx:  0, dy:  1 },
    se: { dx:  1, dy:  1 },
  };
  const { dx, dy } = HANDLES[handleType];
  let resWidth = null;
  let resHeight = null;

  if (dx !== 0) {
    resWidth = Math.max(40, startW + dx * deltaX);
    resHeight = 'auto';
  }
  if (dy !== 0 && dx === 0) {
    resHeight = Math.max(40, startH + dy * deltaY);
    resWidth = 'auto';
  }
  return { width: resWidth, height: resHeight };
}

function calculateEmbedResize(startH, deltaY) {
  return Math.max(120, startH + deltaY);
}

// ---------------------------------------------------------------------------
// Crypto & Token Helpers for Serverless / Cookie Boundary Tests
// ---------------------------------------------------------------------------
const SESSION_SECRET = crypto.createHash('sha256').update('leatherbound-master-session-salt-v3').digest();

function encryptSessionToken(key, secret = SESSION_SECRET) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', secret, iv);
  const encrypted = Buffer.concat([cipher.update(key), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + '.' + authTag.toString('hex') + '.' + encrypted.toString('hex');
}

// ---------------------------------------------------------------------------
// Main Test Suite
// ---------------------------------------------------------------------------

describe('Tier 5: Adversarial Boundary & Code Coverage Analysis', () => {

  // =========================================================================
  // 1. PROXY ERROR HANDLING & RESILIENCE TESTS
  // =========================================================================
  describe('Area 1: Proxy Error Handling (DNS, Timeouts, 500s, Redirect Loops)', () => {
    let server;
    let mockUpstream;
    let mockPort;
    let mockUrl;

    before(async () => {
      mockPort = await getFreePort();
      mockUrl = `http://127.0.0.1:${mockPort}`;

      mockUpstream = http.createServer((req, res) => {
        const u = new URL(req.url, mockUrl);

        // Infinite redirect loop (hop counter test)
        if (u.pathname === '/infinite-redirect') {
          const hop = parseInt(u.searchParams.get('hop') || '0', 10);
          res.writeHead(302, {
            'Location': `${mockUrl}/infinite-redirect?hop=${hop + 1}`,
            'X-Hop-Count': String(hop),
          });
          res.end();
          return;
        }

        // Malformed redirect Location header
        if (u.pathname === '/bad-redirect') {
          res.writeHead(302, {
            'Location': 'http://[invalid-ipv6-address-syntax',
          });
          res.end();
          return;
        }

        // Upstream 500 Internal Server Error with blocking headers
        if (u.pathname === '/upstream-500') {
          res.writeHead(500, {
            'Content-Type': 'text/html; charset=utf-8',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "frame-ancestors 'none'",
            'Cross-Origin-Opener-Policy': 'same-origin',
          });
          res.end('<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body><h1>Server Error</h1></body></html>');
          return;
        }

        // Upstream 503 Service Unavailable
        if (u.pathname === '/upstream-503') {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Service Unavailable', retryAfter: 120 }));
          return;
        }

        res.writeHead(404);
        res.end();
      });

      await new Promise((resolve) => mockUpstream.listen(mockPort, '127.0.0.1', resolve));
      server = await spawnTestServer();
    });

    after(async () => {
      if (server) await server.stop();
      if (mockUpstream) {
        await new Promise((resolve) => mockUpstream.close(resolve));
      }
    });

    test('handles DNS failure (non-existent domain) gracefully with HTTP 502', async () => {
      const badDomainUrl = 'http://non-existent-domain-test-1234567890abcdef.invalid/page';
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(badDomainUrl)}`);
      assert.equal(res.status, 502);
      const body = await res.json();
      assert.ok(body.error, 'Should contain error description');
      assert.ok(/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(body.error));
    });

    test('handles proxy-api DNS failure gracefully with HTTP 502', async () => {
      const badDomainUrl = 'http://non-existent-domain-test-1234567890abcdef.invalid/api/v1';
      const res = await fetch(`${server.baseUrl}/api/proxy-api?url=${encodeURIComponent(badDomainUrl)}`);
      assert.equal(res.status, 502);
    });

    test('handles link-preview DNS failure gracefully with { ok: false }', async () => {
      const badDomainUrl = 'http://non-existent-domain-test-1234567890abcdef.invalid/page';
      const res = await fetch(`${server.baseUrl}/api/link-preview?url=${encodeURIComponent(badDomainUrl)}`);
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.ok, false);
    });

    test('terminates redirect loops after 8 hops without hanging or crashing', async () => {
      const startLoopUrl = `${mockUrl}/infinite-redirect?hop=0`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(startLoopUrl)}`, {
        redirect: 'manual',
      });
      // After 8 hops, the proxy stops following and returns the 302 response with headers
      assert.equal(res.status, 302);
      assert.ok(res.headers.get('location').includes('infinite-redirect'));
    });

    test('handles malformed redirect Location header with HTTP 502', async () => {
      const badRedirectUrl = `${mockUrl}/bad-redirect`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(badRedirectUrl)}`);
      assert.equal(res.status, 502);
    });

    test('passes upstream 500 error status while stripping blocking headers', async () => {
      const upstream500Url = `${mockUrl}/upstream-500`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(upstream500Url)}`);
      assert.equal(res.status, 500);

      // Verify blocking headers are stripped even on 500 errors
      assert.equal(res.headers.get('content-security-policy'), null);
      assert.equal(res.headers.get('cross-origin-opener-policy'), null);
      assert.equal(res.headers.get('x-frame-options'), 'ALLOWALL');

      const html = await res.text();
      assert.ok(html.includes('Server Error'));
      assert.ok(html.includes('<base href='));
    });

    test('passes upstream 503 error on /api/proxy-api cleanly', async () => {
      const upstream503Url = `${mockUrl}/upstream-503`;
      const res = await fetch(`${server.baseUrl}/api/proxy-api?url=${encodeURIComponent(upstream503Url)}`);
      assert.equal(res.status, 503);
      const body = await res.json();
      assert.equal(body.error, 'Service Unavailable');
    });

    test('rejects non-http/https protocols (e.g. file://, gopher://, ftp://)', async () => {
      const fileUrl = 'file:///etc/passwd';
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(fileUrl)}`);
      assert.equal(res.status, 400);
      const body = await res.json();
      assert.equal(body.error, 'Unsupported protocol');

      const ftpUrl = 'ftp://ftp.example.com/file.txt';
      const resFtp = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(ftpUrl)}`);
      assert.equal(resFtp.status, 400);
    });

    test('rejects malformed URLs on /api/proxy and /api/proxy-api', async () => {
      const res1 = await fetch(`${server.baseUrl}/api/proxy?url=not_a_valid_url`);
      assert.equal(res1.status, 400);

      const res2 = await fetch(`${server.baseUrl}/api/proxy?url=`);
      assert.equal(res2.status, 400);

      const res3 = await fetch(`${server.baseUrl}/api/proxy-api?url=`);
      assert.equal(res3.status, 400);

      const res4 = await fetch(`${server.baseUrl}/api/proxy-api?url=:::bad:::`);
      assert.equal(res4.status, 400);
    });
  });

  // =========================================================================
  // 2. YOUTUBE & VIDEO URL PARSING ADVERSARIAL EDGE CASES
  // =========================================================================
  describe('Area 2: YouTube URL Parsing & Direct Embed Boundary Cases', () => {

    test('correctly extracts video ID from YouTube URLs with complex query parameters', () => {
      const urls = [
        'https://www.youtube.com/watch?feature=shared&v=dQw4w9WgXcQ&t=42s',
        'https://www.youtube.com/watch?param1=foo&param2=bar&v=dQw4w9WgXcQ&index=5',
        'https://www.youtube.com/watch?v=dQw4w9WgXcQ&ab_channel=RickAstley',
        'https://youtube.com/watch?v=dQw4w9WgXcQ',
      ];
      for (const u of urls) {
        assert.equal(parseYouTubeId(u), 'dQw4w9WgXcQ', `Failed on ${u}`);
      }
    });

    test('correctly extracts video ID from youtu.be shortlinks with timestamps and tracking parameters', () => {
      const urls = [
        'https://youtu.be/dQw4w9WgXcQ?t=120s',
        'https://youtu.be/dQw4w9WgXcQ?si=abcdef123456789',
        'https://youtu.be/dQw4w9WgXcQ',
        'http://youtu.be/dQw4w9WgXcQ',
      ];
      for (const u of urls) {
        assert.equal(parseYouTubeId(u), 'dQw4w9WgXcQ', `Failed on ${u}`);
      }
    });

    test('correctly extracts video ID from YouTube Shorts and Mobile URLs', () => {
      const urls = [
        'https://www.youtube.com/shorts/dQw4w9WgXcQ',
        'https://www.youtube.com/shorts/dQw4w9WgXcQ?feature=share',
        'https://m.youtube.com/shorts/dQw4w9WgXcQ',
        'https://m.youtube.com/watch?v=dQw4w9WgXcQ',
        'https://m.youtube.com/watch?feature=related&v=dQw4w9WgXcQ',
      ];
      for (const u of urls) {
        assert.equal(parseYouTubeId(u), 'dQw4w9WgXcQ', `Failed on ${u}`);
      }
    });

    test('correctly extracts video ID from YouTube embed and nocookie URLs', () => {
      const urls = [
        'https://www.youtube.com/embed/dQw4w9WgXcQ',
        'https://www.youtube.com/embed/dQw4w9WgXcQ?autoplay=1',
        'https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ',
        'https://www.youtube.com/v/dQw4w9WgXcQ',
      ];
      for (const u of urls) {
        assert.equal(parseYouTubeId(u), 'dQw4w9WgXcQ', `Failed on ${u}`);
      }
    });

    test('gracefully rejects playlist-only URLs and channels without video ID', () => {
      const nonVideoUrls = [
        'https://www.youtube.com/playlist?list=PLrEnWoR732-B41UnyVTXMaPpGW71daAG4',
        'https://www.youtube.com/@RickAstleyYT',
        'https://www.youtube.com/channel/UCuAXFkgsw1L7xaCfnd5JJOw',
        'https://www.youtube.com/feed/trending',
      ];
      for (const u of nonVideoUrls) {
        assert.equal(parseYouTubeId(u), null, `Expected null for playlist/channel URL: ${u}`);
      }
    });

    test('gracefully rejects malformed and boundary inputs without throwing exceptions', () => {
      const malformedInputs = [
        '',
        null,
        undefined,
        12345,
        'not a url at all',
        'http://',
        'https://youtube.com/watch',
        'https://youtube.com/watch?v=',
        'https://youtube.com/watch?v=abc',     // < 6 chars
        'https://youtube.com/watch?v=12345',   // < 6 chars (5 chars)
        'https://youtu.be/',
        'https://youtu.be/short',               // < 6 chars (5 chars)
        'https://youtu.be/a',                   // 1 char
        'https://www.youtube.com/shorts/',      // empty shorts ID
        'https://www.youtube.com/embed/',       // empty embed ID
      ];
      for (const input of malformedInputs) {
        assert.doesNotThrow(() => {
          const res = parseYouTubeId(input);
          assert.equal(res, null, `Expected null for invalid input: ${input}`);
        });
      }
    });

    test('CRITICAL: getIframeSrcForUrl ALWAYS generates youtube-nocookie.com embed and NEVER /api/proxy', () => {
      const testCases = [
        'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        'https://youtu.be/dQw4w9WgXcQ',
        'https://www.youtube.com/shorts/dQw4w9WgXcQ',
        'https://m.youtube.com/watch?v=dQw4w9WgXcQ',
      ];
      for (const u of testCases) {
        const iframeSrc = getIframeSrcForUrl(u);
        assert.equal(iframeSrc, 'https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ?autoplay=0&rel=0&modestbranding=1');
        assert.ok(!iframeSrc.includes('/api/proxy'), 'Must NOT route YouTube embeds through reverse proxy!');
      }
    });

    test('Vimeo parser correctly extracts numeric IDs from various Vimeo URL patterns', () => {
      const vimeoCases = [
        ['https://vimeo.com/76979871', '76979871'],
        ['https://vimeo.com/video/76979871', '76979871'],
        ['https://player.vimeo.com/video/76979871', '76979871'],
        ['https://vimeo.com/channels/staffpicks/76979871', '76979871'],
        ['https://vimeo.com/groups/motion/videos/76979871', '76979871'],
      ];
      for (const [url, expectedId] of vimeoCases) {
        assert.equal(parseVimeoId(url), expectedId, `Failed on Vimeo URL: ${url}`);
        const iframeSrc = getIframeSrcForUrl(url);
        assert.equal(iframeSrc, `https://player.vimeo.com/video/${expectedId}`);
      }
    });
  });

  // =========================================================================
  // 3. 8-HANDLE IMAGE RESIZING & EMBED RESIZING ADVERSARIAL TESTS
  // =========================================================================
  describe('Area 3: 8-Handle Image Resizing & Resizer Boundary Calculations', () => {

    test('East (E) handle scales width positively and clamps to 40px on negative deltas', () => {
      const initialW = 200;
      const initialH = 150;

      // Positive expansion
      const exp = calculateHandleResize('e', initialW, initialH, 50, 0);
      assert.equal(exp.width, 250);
      assert.equal(exp.height, 'auto');

      // Extreme negative drag (e.g. -500px)
      const clamped = calculateHandleResize('e', initialW, initialH, -500, 0);
      assert.equal(clamped.width, 40, 'Width must clamp to minimum 40px');
      assert.equal(clamped.height, 'auto');
    });

    test('West (W) handle inverts deltaX: dragging left expands, dragging right shrinks', () => {
      const initialW = 200;
      const initialH = 150;

      // Dragging left (deltaX = -80) should enlarge width (200 + (-1 * -80) = 280)
      const enlarge = calculateHandleResize('w', initialW, initialH, -80, 0);
      assert.equal(enlarge.width, 280);
      assert.equal(enlarge.height, 'auto');

      // Dragging right beyond origin (deltaX = +300) should clamp to 40px
      const clamped = calculateHandleResize('w', initialW, initialH, 300, 0);
      assert.equal(clamped.width, 40);
      assert.equal(clamped.height, 'auto');
    });

    test('South (S) and North (N) handles perform pure vertical height resizing', () => {
      const initialW = 200;
      const initialH = 150;

      // South positive expansion
      const sExp = calculateHandleResize('s', initialW, initialH, 0, 100);
      assert.equal(sExp.height, 250);
      assert.equal(sExp.width, 'auto');

      // South extreme shrinkage clamp
      const sClamp = calculateHandleResize('s', initialW, initialH, 0, -400);
      assert.equal(sClamp.height, 40);

      // North upward expansion (deltaY = -120 -> 150 + (-1 * -120) = 270)
      const nExp = calculateHandleResize('n', initialW, initialH, 0, -120);
      assert.equal(nExp.height, 270);
      assert.equal(nExp.width, 'auto');

      // North downward shrinkage clamp (deltaY = +300)
      const nClamp = calculateHandleResize('n', initialW, initialH, 0, 300);
      assert.equal(nClamp.height, 40);
    });

    test('All 4 corner handles (NW, NE, SW, SE) update width and preserve aspect ratio', () => {
      const initialW = 300;
      const initialH = 200;

      const corners = ['nw', 'ne', 'sw', 'se'];
      for (const handle of corners) {
        const res = calculateHandleResize(handle, initialW, initialH, 50, 50);
        assert.ok(typeof res.width === 'number', `Width should be number for ${handle}`);
        assert.equal(res.height, 'auto', `Height should be auto to preserve aspect ratio for ${handle}`);
      }
    });

    test('Handles zero initial dimensions without returning NaN or negative numbers', () => {
      const zeroW = 0;
      const zeroH = 0;

      const resE = calculateHandleResize('e', zeroW, zeroH, -100, 0);
      assert.equal(resE.width, 40, 'Should clamp to 40 even with 0 start width');

      const resS = calculateHandleResize('s', zeroW, zeroH, 0, -100);
      assert.equal(resS.height, 40, 'Should clamp to 40 even with 0 start height');
    });

    test('Live embed frame height resizer clamps to minimum 120px', () => {
      const initialH = 300;

      // Expansion
      assert.equal(calculateEmbedResize(initialH, 150), 450);

      // Shrinkage within bounds
      assert.equal(calculateEmbedResize(initialH, -100), 200);

      // Extreme shrinkage below clamp (e.g. -500px)
      assert.equal(calculateEmbedResize(initialH, -500), 120, 'Embed height must clamp to min 120px');
    });
  });

  // =========================================================================
  // 4. BOOKSHELF DRAWER & MULTI-BOOK CRUD ADVERSARIAL TESTS
  // =========================================================================
  describe('Area 4: Bookshelf Drawer Edge Cases (Active Deletion, 1-Book Invariant, Ghost IDs)', () => {
    let server;
    let sessionCookie;
    let book1Id;
    let book2Id;
    let book3Id;

    before(async () => {
      server = await spawnTestServer();

      // Setup initial vault
      const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'AdversarialPassword2026!' }),
      });
      sessionCookie = extractCookie(setupRes);
      const setupJson = await setupRes.json();
      book1Id = setupJson.activeBookId;

      // Create Book 2
      const b2Res = await fetch(`${server.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ title: 'Book 2 (Pine)', coverColor: 'green' }),
      });
      const b2Json = await b2Res.json();
      book2Id = b2Json.activeBookId;

      // Create Book 3
      const b3Res = await fetch(`${server.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ title: 'Book 3 (Navy)', coverColor: 'navy' }),
      });
      const b3Json = await b3Res.json();
      book3Id = b3Json.activeBookId;
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('deleting the currently active book realigns activeBookId to a remaining book', async () => {
      // Currently active is book3Id
      const delRes = await fetch(`${server.baseUrl}/api/books/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ bookId: book3Id }),
      });
      assert.equal(delRes.status, 200);
      const delJson = await delRes.json();
      assert.equal(delJson.ok, true);
      assert.equal(delJson.vault.books.length, 2);

      // Active book must have realigned away from book3Id
      assert.notEqual(delJson.activeBookId, book3Id);
      assert.ok([book1Id, book2Id].includes(delJson.activeBookId));

      // Subsequent GET /api/notebook reflects new active book
      const nbRes = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      const nbJson = await nbRes.json();
      assert.equal(nbJson.notebook.id, delJson.activeBookId);
    });

    test('switching to a nonexistent book ID returns 404 Not Found without modifying active book', async () => {
      const switchRes = await fetch(`${server.baseUrl}/api/books/switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ bookId: 'ghost-nonexistent-book-9999' }),
      });
      assert.equal(switchRes.status, 404);
      const json = await switchRes.json();
      assert.equal(json.error, 'Book not found.');
    });

    test('renaming a nonexistent book ID returns 404 Not Found without modifying vault', async () => {
      const renameRes = await fetch(`${server.baseUrl}/api/books/rename`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ bookId: 'ghost-nonexistent-book-9999', title: 'Ghost Title' }),
      });
      assert.equal(renameRes.status, 404);
      const json = await renameRes.json();
      assert.equal(json.error, 'Book not found.');
    });

    test('creating a book with empty or whitespace title normalizes to "New Notebook"', async () => {
      const createRes = await fetch(`${server.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ title: '   ', coverColor: 'burgundy' }),
      });
      assert.equal(createRes.status, 200);
      const json = await createRes.json();
      assert.equal(json.notebook.title, 'New Notebook');
      assert.equal(json.notebook.coverColor, 'burgundy');

      // Clean up this extra book
      await fetch(`${server.baseUrl}/api/books/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ bookId: json.notebook.id }),
      });
    });

    test('deleting when only 1 book exists is strictly blocked (minimum 1 book invariant)', async () => {
      // First delete book2Id so only 1 book remains
      const del2Res = await fetch(`${server.baseUrl}/api/books/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ bookId: book2Id }),
      });
      assert.equal(del2Res.status, 200);
      const del2Json = await del2Res.json();
      assert.equal(del2Json.vault.books.length, 1);
      const lastRemainingId = del2Json.vault.books[0].id;

      // Attempt to delete the final remaining book
      const finalDelRes = await fetch(`${server.baseUrl}/api/books/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${sessionCookie}` },
        body: JSON.stringify({ bookId: lastRemainingId }),
      });
      assert.equal(finalDelRes.status, 400);
      const finalDelJson = await finalDelRes.json();
      assert.equal(finalDelJson.error, 'You must have at least one notebook.');

      // Verify book still exists
      const booksListRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      const booksListJson = await booksListRes.json();
      assert.equal(booksListJson.books.length, 1);
    });
  });

  // =========================================================================
  // 5. SESSION COOKIE BOUNDARY & CRYPTO RESILIENCE TESTS
  // =========================================================================
  describe('Area 5: Session Cookie Security Attributes & Token Boundary Tests', () => {

    test('sets SameSite=Lax on standard local HTTP requests (without Secure flag)', async () => {
      const server = await spawnTestServer();
      try {
        const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'HttpPassword123' }),
        });
        assert.equal(setupRes.status, 200);
        const setCookieHeader = setupRes.headers.get('set-cookie');
        assert.ok(setCookieHeader, 'Set-Cookie header must be present');
        assert.ok(setCookieHeader.includes('SameSite=Lax'), 'Local HTTP must use SameSite=Lax');
        assert.ok(!setCookieHeader.includes('Secure'), 'Local HTTP must not set Secure attribute');
        assert.ok(setCookieHeader.includes('HttpOnly'));
        assert.ok(setCookieHeader.includes('Path=/'));
      } finally {
        await server.stop();
      }
    });

    test('sets SameSite=None; Secure on HTTPS requests via x-forwarded-proto', async () => {
      const server = await spawnTestServer();
      try {
        const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-forwarded-proto': 'https',
          },
          body: JSON.stringify({ password: 'HttpsPassword123' }),
        });
        assert.equal(setupRes.status, 200);
        const setCookieHeader = setupRes.headers.get('set-cookie');
        assert.ok(setCookieHeader, 'Set-Cookie header must be present');
        assert.ok(setCookieHeader.includes('SameSite=None'), 'HTTPS must use SameSite=None');
        assert.ok(setCookieHeader.includes('Secure'), 'HTTPS must include Secure flag');
        assert.ok(setCookieHeader.includes('HttpOnly'));
      } finally {
        await server.stop();
      }
    });

    test('sets SameSite=None; Secure automatically when process.env.VERCEL=1 is enabled', async () => {
      const vercelTmpDir = path.join('/tmp', 'data');
      try {
        if (fs.existsSync(vercelTmpDir)) {
          fs.rmSync(vercelTmpDir, { recursive: true, force: true });
        }
      } catch (e) {}

      const server = await spawnTestServer({ isVercel: true });
      try {
        const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'VercelPassword123' }),
        });
        assert.equal(setupRes.status, 200);
        const setCookieHeader = setupRes.headers.get('set-cookie');
        assert.ok(setCookieHeader.includes('SameSite=None'));
        assert.ok(setCookieHeader.includes('Secure'));
      } finally {
        await server.stop();
        try {
          if (fs.existsSync(vercelTmpDir)) {
            fs.rmSync(vercelTmpDir, { recursive: true, force: true });
          }
        } catch (e) {}
      }
    });

    test('rejects tampered and malformed session tokens with 401 Unauthorized', async () => {
      const server = await spawnTestServer();
      try {
        const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'AuthPassword123' }),
        });
        const validCookie = extractCookie(setupRes);
        const decodedToken = decodeURIComponent(validCookie);
        const parts = decodedToken.split('.');
        assert.equal(parts.length, 3, 'Valid token must have 3 parts: IV.Tag.Ciphertext');

        const badTokens = [
          // 1. Missing parts
          parts[0],
          parts[0] + '.' + parts[1],
          // 2. Extra parts
          decodedToken + '.extrapart',
          // 3. Non-hex characters
          'not-hex-at-all.invalid-tag.invalid-ciphertext',
          // 4. Bit-flipped IV
          '00' + parts[0].slice(2) + '.' + parts[1] + '.' + parts[2],
          // 5. Bit-flipped AuthTag (GCM verification failure)
          parts[0] + '.' + (parts[1].slice(0, 2) === 'ff' ? '00' : 'ff') + parts[1].slice(2) + '.' + parts[2],
          // 6. Bit-flipped Ciphertext
          parts[0] + '.' + parts[1] + '.' + '00' + parts[2].slice(2),
          // 7. Token encrypted with different secret key
          encryptSessionToken(crypto.randomBytes(32), crypto.randomBytes(32)),
          // 8. Empty / garbage string
          '',
          '   ',
          'null',
        ];

        for (const badToken of badTokens) {
          const res = await fetch(`${server.baseUrl}/api/notebook`, {
            headers: { Cookie: `notebook_session=${encodeURIComponent(badToken)}` },
          });
          assert.equal(res.status, 401, `Failed to reject tampered token: ${badToken}`);
        }
      } finally {
        await server.stop();
      }
    });

    test('POST /api/lock clears session cookie with Max-Age=0', async () => {
      const server = await spawnTestServer();
      try {
        await fetch(`${server.baseUrl}/api/setup`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'LockTestPassword123' }),
        });

        const lockRes = await fetch(`${server.baseUrl}/api/lock`, { method: 'POST' });
        assert.equal(lockRes.status, 200);
        const setCookieHeader = lockRes.headers.get('set-cookie');
        assert.ok(setCookieHeader, 'Must send Set-Cookie header on lock');
        assert.ok(setCookieHeader.includes('Max-Age=0') || setCookieHeader.includes('expires='), 'Must expire cookie');
        assert.ok(setCookieHeader.includes('notebook_session=;'));
      } finally {
        await server.stop();
      }
    });
  });

});
