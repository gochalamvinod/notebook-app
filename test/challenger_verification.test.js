const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const http = require('http');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawnTestServer, extractCookie } = require('./test_helper.js');

describe('Empirical Challenger Independent Verification Suite', () => {

  // -------------------------------------------------------------------------
  // 1. YouTube nocookie V8 crash prevention & URL classification
  // -------------------------------------------------------------------------
  describe('Requirement 1: YouTube & Vimeo Zero-Crash Isolation', () => {
    // Pure function logic mirroring client-side parseYouTubeId & getIframeSrcForUrl
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

    function getIframeSrcForUrl(url) {
      if (!url) return '/api/proxy?url=about:blank';
      const ytId = parseYouTubeId(url);
      if (ytId) {
        return `https://www.youtube-nocookie.com/embed/${ytId}?autoplay=0&rel=0&modestbranding=1`;
      }
      return '/api/proxy?url=' + encodeURIComponent(url);
    }

    test('All YouTube variants resolve to youtube-nocookie.com and never proxy', () => {
      const urls = [
        'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        'https://m.youtube.com/watch?v=dQw4w9WgXcQ&feature=share',
        'https://youtu.be/dQw4w9WgXcQ?t=42',
        'https://www.youtube.com/shorts/dQw4w9WgXcQ',
        'https://www.youtube.com/embed/dQw4w9WgXcQ',
        'https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ?autoplay=1',
      ];

      for (const u of urls) {
        const id = parseYouTubeId(u);
        assert.equal(id, 'dQw4w9WgXcQ');
        const src = getIframeSrcForUrl(u);
        assert.ok(src.startsWith('https://www.youtube-nocookie.com/embed/dQw4w9WgXcQ'), `URL ${u} did not resolve to nocookie embed`);
        assert.ok(!src.includes('/api/proxy'), `URL ${u} leaked into proxy route!`);
      }
    });

    test('Non-YouTube URLs safely route through proxy', () => {
      const src = getIframeSrcForUrl('https://en.wikipedia.org/wiki/Leather');
      assert.equal(src, '/api/proxy?url=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FLeather');
    });
  });

  // -------------------------------------------------------------------------
  // 2. In-App Web Search Engine (/api/search)
  // -------------------------------------------------------------------------
  describe('Requirement 2: In-App Search Engine Endpoint Robustness', () => {
    let server;

    before(async () => {
      server = await spawnTestServer();
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('Handles empty and whitespace queries gracefully', async () => {
      const res = await fetch(`${server.baseUrl}/api/search?q=`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.deepEqual(json.results, []);
    });

    test('Handles adversarial queries without throwing or crashing', async () => {
      const queries = [
        '<script>alert("XSS")</script>',
        'SELECT * FROM vault WHERE 1=1;',
        'https://google.com/search?q=test',
        '🦆 📚 🔒 Unicode Search Probe',
        'A'.repeat(500),
      ];

      for (const q of queries) {
        const res = await fetch(`${server.baseUrl}/api/search?q=${encodeURIComponent(q)}`);
        assert.equal(res.status, 200);
        const json = await res.json();
        assert.equal(json.ok, true);
        assert.ok(Array.isArray(json.results));
      }
    });
  });

  // -------------------------------------------------------------------------
  // 3. Streaming Reverse Proxy with Decompression & Header Neutralization
  // -------------------------------------------------------------------------
  describe('Requirement 3: Proxy Multi-Decompression & Header Stripping', () => {
    let server;
    let mockUpstream;
    let upstreamPort;

    before(async () => {
      // Create a mock upstream server capable of gzip, brotli, deflate, and frame-blocking headers
      mockUpstream = http.createServer((req, res) => {
        if (req.url === '/gzip-page') {
          const body = '<html><head><title>Gzip Target</title></head><body><h1>Decompressed Gzip!</h1></body></html>';
          const gzipped = zlib.gzipSync(Buffer.from(body));
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Encoding': 'gzip',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "frame-ancestors 'none'",
            'Cross-Origin-Opener-Policy': 'same-origin',
          });
          return res.end(gzipped);
        }
        if (req.url === '/brotli-page') {
          const body = '<html><head><title>Brotli Target</title></head><body><h1>Decompressed Brotli!</h1></body></html>';
          const brotli = zlib.brotliCompressSync(Buffer.from(body));
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Encoding': 'br',
            'X-Frame-Options': 'SAMEORIGIN',
          });
          return res.end(brotli);
        }
        if (req.url === '/deflate-page') {
          const body = '<html><head><title>Deflate Target</title></head><body><h1>Decompressed Deflate!</h1></body></html>';
          const deflated = zlib.deflateSync(Buffer.from(body));
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Encoding': 'deflate',
          });
          return res.end(deflated);
        }
        if (req.url === '/bad-decompression') {
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Encoding': 'gzip',
          });
          return res.end(Buffer.from('This is NOT valid gzip data'));
        }
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      });

      await new Promise((resolve) => {
        mockUpstream.listen(0, '127.0.0.1', () => {
          upstreamPort = mockUpstream.address().port;
          resolve();
        });
      });

      server = await spawnTestServer();
    });

    after(async () => {
      if (server) await server.stop();
      if (mockUpstream) mockUpstream.close();
    });

    test('Proxy decompresses GZIP stream and strips blocking headers', async () => {
      const targetUrl = `http://127.0.0.1:${upstreamPort}/gzip-page`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(targetUrl)}`);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('x-frame-options'), 'ALLOWALL');
      assert.equal(res.headers.get('content-security-policy'), null);
      assert.equal(res.headers.get('cross-origin-opener-policy'), null);

      const html = await res.text();
      assert.ok(html.includes('Decompressed Gzip!'));
      assert.ok(html.includes('<base href='));
    });

    test('Proxy decompresses Brotli (br) stream cleanly', async () => {
      const targetUrl = `http://127.0.0.1:${upstreamPort}/brotli-page`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(targetUrl)}`);
      assert.equal(res.status, 200);
      const html = await res.text();
      assert.ok(html.includes('Decompressed Brotli!'));
    });

    test('Proxy decompresses Deflate stream cleanly', async () => {
      const targetUrl = `http://127.0.0.1:${upstreamPort}/deflate-page`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(targetUrl)}`);
      assert.equal(res.status, 200);
      const html = await res.text();
      assert.ok(html.includes('Decompressed Deflate!'));
    });

    test('Proxy handles decompression failure without server crash', async () => {
      const targetUrl = `http://127.0.0.1:${upstreamPort}/bad-decompression`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(targetUrl)}`);
      assert.equal(res.status, 502);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Link Previews Endpoint (/api/link-preview)
  // -------------------------------------------------------------------------
  describe('Requirement 4: Link Preview Unfurling & Fallbacks', () => {
    let server;
    let mockSite;
    let sitePort;

    before(async () => {
      mockSite = http.createServer((req, res) => {
        if (req.url === '/rich-article') {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
          return res.end(`
            <!DOCTYPE html>
            <html>
            <head>
              <title>Standard Fallback Title</title>
              <meta property="og:title" content="OpenGraph Ancient Leather Binding">
              <meta property="og:description" content="A comprehensive historical study of leather tooling.">
              <meta property="og:image" content="https://example.com/leather.jpg">
            </head>
            <body>Content</body>
            </html>
          `);
        }
        if (req.url === '/non-html') {
          res.writeHead(200, { 'Content-Type': 'application/pdf' });
          return res.end(Buffer.from('%PDF-1.4 dummy pdf'));
        }
        res.writeHead(404);
        res.end();
      });

      await new Promise((resolve) => {
        mockSite.listen(0, '127.0.0.1', () => {
          sitePort = mockSite.address().port;
          resolve();
        });
      });

      server = await spawnTestServer();
    });

    after(async () => {
      if (server) await server.stop();
      if (mockSite) mockSite.close();
    });

    test('Extracts OpenGraph metadata accurately', async () => {
      const targetUrl = `http://127.0.0.1:${sitePort}/rich-article`;
      const res = await fetch(`${server.baseUrl}/api/link-preview?url=${encodeURIComponent(targetUrl)}`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.title, 'OpenGraph Ancient Leather Binding');
      assert.equal(json.description, 'A comprehensive historical study of leather tooling.');
      assert.equal(json.image, 'https://example.com/leather.jpg');
      assert.equal(json.domain, '127.0.0.1');
    });

    test('Returns { ok: false } for non-HTML resources without crashing', async () => {
      const targetUrl = `http://127.0.0.1:${sitePort}/non-html`;
      const res = await fetch(`${server.baseUrl}/api/link-preview?url=${encodeURIComponent(targetUrl)}`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, false);
    });
  });

  // -------------------------------------------------------------------------
  // 5. Multi-Book Library Management & 1-Book Invariant
  // -------------------------------------------------------------------------
  describe('Requirement 5: Multi-Book Library Management & Theme Invariants', () => {
    let server;
    let cookie;
    const password = 'ChallengerPass_2026!';

    before(async () => {
      server = await spawnTestServer();
      const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(setupRes.status, 200);
      cookie = extractCookie(setupRes);
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('Full Multi-Book lifecycle: create, list, switch, rename, delete', async () => {
      // 1. Create Book 2
      const createRes = await fetch(`${server.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ title: 'Emerald Tome', coverColor: 'emerald' }),
      });
      assert.equal(createRes.status, 200);
      const createJson = await createRes.json();
      const book2Id = createJson.notebook.id;
      assert.equal(createJson.notebook.title, 'Emerald Tome');
      assert.equal(createJson.notebook.coverColor, 'emerald');

      // 2. List books
      const listRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(listRes.status, 200);
      const listJson = await listRes.json();
      assert.equal(listJson.books.length, 2);
      assert.equal(listJson.activeBookId, book2Id);

      // 3. Rename Book 2
      const renameRes = await fetch(`${server.baseUrl}/api/books/rename`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ bookId: book2Id, title: 'Renamed Emerald Codex', coverColor: 'navy' }),
      });
      assert.equal(renameRes.status, 200);

      // 4. Switch back to Book 1
      const initialBookId = listJson.books.find(b => b.id !== book2Id).id;
      const switchRes = await fetch(`${server.baseUrl}/api/books/switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ bookId: initialBookId }),
      });
      assert.equal(switchRes.status, 200);
      const switchJson = await switchRes.json();
      assert.equal(switchJson.activeBookId, initialBookId);

      // 5. Delete Book 2
      const delRes = await fetch(`${server.baseUrl}/api/books/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ bookId: book2Id }),
      });
      assert.equal(delRes.status, 200);

      // 6. Attempt deleting last remaining book -> MUST BE BLOCKED
      const delLastRes = await fetch(`${server.baseUrl}/api/books/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ bookId: initialBookId }),
      });
      assert.equal(delLastRes.status, 400, 'Must block deleting the sole remaining notebook');
    });
  });

  // -------------------------------------------------------------------------
  // 6. File Image Persistence & Path Traversal Guard
  // -------------------------------------------------------------------------
  describe('Requirement 6: File Image Persistence & Path Traversal Defense', () => {
    let server;
    let cookie;
    const password = 'ImageChallengerPass_2026!';
    const samplePng = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

    before(async () => {
      server = await spawnTestServer();
      const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(setupRes.status, 200);
      cookie = extractCookie(setupRes);
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('Uploads image, retrieves binary, deletes image, prevents traversal', async () => {
      // 1. Upload
      const upRes = await fetch(`${server.baseUrl}/api/images`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ data: `data:image/png;base64,${samplePng}`, ext: 'png' }),
      });
      assert.equal(upRes.status, 200);
      const upJson = await upRes.json();
      assert.ok(upJson.url);
      const filename = upJson.filename;

      // 2. Fetch authenticated
      const getRes = await fetch(`${server.baseUrl}/images/${filename}`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(getRes.status, 200);
      const buf = Buffer.from(await getRes.arrayBuffer());
      assert.deepEqual(buf, Buffer.from(samplePng, 'base64'));

      // 3. Fetch unauthenticated -> 401
      const anonRes = await fetch(`${server.baseUrl}/images/${filename}`);
      assert.equal(anonRes.status, 401);

      // 4. Path traversal attempt -> 400 or 403
      const travRes = await fetch(`${server.baseUrl}/images/..%2f..%2fpackage.json`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.ok([400, 403, 404].includes(travRes.status));

      // 5. Delete image
      const delRes = await fetch(`${server.baseUrl}/api/images/${filename}`, {
        method: 'DELETE',
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(delRes.status, 200);

      // 6. Fetch after delete -> 404
      const getAfterDel = await fetch(`${server.baseUrl}/images/${filename}`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(getAfterDel.status, 404);
    });
  });
});
