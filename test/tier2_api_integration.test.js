const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const zlib = require('node:zlib');
const path = require('node:path');
const fs = require('node:fs');
const { spawnTestServer, extractCookie, getFreePort } = require('./test_helper.js');

describe('Tier 2: API Integration Tests', () => {
  let server;
  let mockTargetServer;
  let mockTargetPort;
  let mockTargetUrl;

  let sessionCookie = null;
  const masterPassword = 'MySecretVaultPassword123!';

  before(async () => {
    // 1. Start a local mock target server for testing Proxy & Link Preview
    mockTargetPort = await getFreePort();
    mockTargetUrl = `http://127.0.0.1:${mockTargetPort}`;
    mockTargetServer = http.createServer((req, res) => {
      const url = new URL(req.url, mockTargetUrl);
      if (url.pathname === '/preview-page') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'X-Frame-Options': 'DENY',
          'Content-Security-Policy': "frame-ancestors 'none'",
        });
        res.end(`<!DOCTYPE html>
<html>
<head>
  <title>Mock Target Page Title</title>
  <meta name="description" content="A comprehensive preview description">
  <meta property="og:title" content="OG Mock Title">
  <meta property="og:description" content="OG Mock Description">
  <meta property="og:image" content="http://127.0.0.1:${mockTargetPort}/test-thumb.jpg">
</head>
<body>
  <h1>Hello from Mock Target</h1>
</body>
</html>`);
        return;
      }
      if (url.pathname === '/compressed-page') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Encoding': 'gzip',
          'X-Frame-Options': 'SAMEORIGIN',
        });
        const gzipped = zlib.gzipSync('<!DOCTYPE html><html><head><title>Gzip</title></head><body><h1>Compressed content</h1></body></html>');
        res.end(gzipped);
        return;
      }
      if (url.pathname === '/api/data') {
        res.writeHead(200, { 'Content-Type': 'application/json', 'X-Custom-Header': 'MockValue' });
        res.end(JSON.stringify({ status: 'live', count: 42 }));
        return;
      }
      if (url.pathname === '/test-thumb.jpg') {
        res.writeHead(200, { 'Content-Type': 'image/jpeg' });
        res.end(Buffer.from([0xff, 0xd8, 0xff, 0xe0]));
        return;
      }
      res.writeHead(404);
      res.end();
    });

    await new Promise((resolve) => mockTargetServer.listen(mockTargetPort, '127.0.0.1', resolve));

    // 2. Start the main isolated Notebook Server
    server = await spawnTestServer();
  });

  after(async () => {
    if (server) await server.stop();
    if (mockTargetServer) {
      await new Promise((resolve) => mockTargetServer.close(resolve));
    }
  });

  describe('Server Status & Setup Lifecycle', () => {
    test('GET /api/status indicates setup is needed when no vault exists', async () => {
      const res = await fetch(`${server.baseUrl}/api/status`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.setupNeeded, true);
      assert.equal(json.unlocked, false);
    });

    test('POST /api/setup rejects invalid passwords (< 4 characters or empty)', async () => {
      const resShort = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: '123' }),
      });
      assert.equal(resShort.status, 400);
      const jsonShort = await resShort.json();
      assert.ok(jsonShort.error.includes('at least 4 characters'));

      const resEmpty = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      assert.equal(resEmpty.status, 400);
    });

    test('POST /api/setup creates vault and returns initial notebook with session cookie', async () => {
      const res = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: masterPassword }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.vault.version, 2);
      assert.equal(json.vault.books.length, 1);
      assert.equal(json.notebook.title, 'My Notebook');
      assert.equal(json.notebook.coverColor, 'brown');

      sessionCookie = extractCookie(res);
      assert.ok(sessionCookie, 'Session cookie notebook_session must be set');
    });

    test('POST /api/setup is blocked when vault already exists', async () => {
      const res = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: masterPassword }),
      });
      assert.equal(res.status, 400);
      const json = await res.json();
      assert.ok(json.error.includes('already exists'));
    });

    test('GET /api/status reports setupNeeded: false and unlocked: true when cookie is provided', async () => {
      const res = await fetch(`${server.baseUrl}/api/status`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.setupNeeded, false);
      assert.equal(json.unlocked, true);
    });
  });

  describe('Lock, Unlock, and Session Protection', () => {
    test('POST /api/lock clears session and revokes access', async () => {
      const res = await fetch(`${server.baseUrl}/api/lock`, {
        method: 'POST',
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);

      // Verify Set-Cookie clears cookie with Max-Age=0
      const setCookie = res.headers.get('set-cookie');
      assert.ok(setCookie.includes('Max-Age=0'));
    });

    test('GET /api/status reports unlocked: false after lock', async () => {
      const res = await fetch(`${server.baseUrl}/api/status`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.setupNeeded, false);
      assert.equal(json.unlocked, false);
    });

    test('Accessing protected endpoints while locked returns 401 Unauthorized', async () => {
      const protectedEndpoints = [
        { path: '/api/notebook', method: 'GET' },
        { path: '/api/notebook', method: 'POST', body: {} },
        { path: '/api/books', method: 'GET' },
        { path: '/api/books/create', method: 'POST', body: { title: 'Test' } },
        { path: '/api/books/switch', method: 'POST', body: { bookId: '123' } },
        { path: '/api/books/rename', method: 'POST', body: { bookId: '123', title: 'New' } },
        { path: '/api/books/delete', method: 'POST', body: { bookId: '123' } },
        { path: '/api/images', method: 'POST', body: { data: 'abc' } },
        { path: '/images/sample.jpg', method: 'GET' },
        { path: '/api/images/sample.jpg', method: 'DELETE' },
        { path: '/api/change-password', method: 'POST', body: { newPassword: '1234' } },
      ];

      for (const ep of protectedEndpoints) {
        const res = await fetch(`${server.baseUrl}${ep.path}`, {
          method: ep.method,
          headers: { 'Content-Type': 'application/json' },
          body: ep.body ? JSON.stringify(ep.body) : undefined,
        });
        assert.equal(res.status, 401, `Endpoint ${ep.method} ${ep.path} must return 401 when locked`);
      }
    });

    test('Accessing protected endpoints with invalid or tampered session cookie returns 401 Unauthorized', async () => {
      const res = await fetch(`${server.baseUrl}/api/books`, {
        headers: { Cookie: 'notebook_session=invalid.tampered.cookie123' },
      });
      assert.equal(res.status, 401);
    });

    test('POST /api/unlock fails with 401 on incorrect password', async () => {
      const res = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'WrongPassword!' }),
      });
      assert.equal(res.status, 401);
      const json = await res.json();
      assert.equal(json.error, 'Incorrect password.');
    });

    test('POST /api/unlock succeeds with correct password and restores session cookie', async () => {
      const res = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: masterPassword }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.vault.version, 2);

      sessionCookie = extractCookie(res);
      assert.ok(sessionCookie);
    });
  });

  describe('Multi-Book Library Management & CRUD', () => {
    let secondBookId = null;
    let initialBookId = null;

    test('GET /api/books returns library listing with activeBookId', async () => {
      const res = await fetch(`${server.baseUrl}/api/books`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.books.length, 1);
      assert.equal(json.books[0].title, 'My Notebook');
      initialBookId = json.activeBookId;
      assert.ok(initialBookId);
    });

    test('POST /api/books/create creates new notebook with custom title and cover theme', async () => {
      const res = await fetch(`${server.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({
          title: 'Emerald Chronicle',
          coverColor: 'green',
        }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.vault.books.length, 2);
      assert.equal(json.notebook.title, 'Emerald Chronicle');
      assert.equal(json.notebook.coverColor, 'green');
      assert.equal(json.activeBookId, json.notebook.id);
      secondBookId = json.notebook.id;
    });

    test('POST /api/books/switch switches active notebook', async () => {
      const res = await fetch(`${server.baseUrl}/api/books/switch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ bookId: initialBookId }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.activeBookId, initialBookId);
      assert.equal(json.notebook.id, initialBookId);
      assert.equal(json.notebook.title, 'My Notebook');
    });

    test('POST /api/books/switch returns 404 for invalid bookId', async () => {
      const res = await fetch(`${server.baseUrl}/api/books/switch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ bookId: 'nonexistent-book-999' }),
      });
      assert.equal(res.status, 404);
    });

    test('POST /api/books/rename updates notebook title and cover theme', async () => {
      const res = await fetch(`${server.baseUrl}/api/books/rename`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({
          bookId: secondBookId,
          title: 'Emerald Tome Renovated',
          coverColor: 'navy',
        }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      const targetBook = json.vault.books.find((b) => b.id === secondBookId);
      assert.equal(targetBook.title, 'Emerald Tome Renovated');
      assert.equal(targetBook.coverColor, 'navy');
    });

    test('POST /api/books/rename returns 404 for non-existent bookId', async () => {
      const res = await fetch(`${server.baseUrl}/api/books/rename`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({
          bookId: 'ghost-book-id',
          title: 'Ghost Title',
        }),
      });
      assert.equal(res.status, 404);
    });

    test('POST /api/books/delete removes notebook and reassigns activeBookId', async () => {
      // First switch to second book
      await fetch(`${server.baseUrl}/api/books/switch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ bookId: secondBookId }),
      });

      // Delete second book
      const res = await fetch(`${server.baseUrl}/api/books/delete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ bookId: secondBookId }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.vault.books.length, 1);
      assert.equal(json.activeBookId, initialBookId);
    });

    test('POST /api/books/delete enforces minimum 1 notebook invariant', async () => {
      const res = await fetch(`${server.baseUrl}/api/books/delete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ bookId: initialBookId }),
      });
      assert.equal(res.status, 400);
      const json = await res.json();
      assert.equal(json.error, 'You must have at least one notebook.');
    });
  });

  describe('Notebook Content CRUD (/api/notebook)', () => {
    test('GET /api/notebook returns full vault and active notebook', async () => {
      const res = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.ok(json.notebook);
      assert.ok(json.vault);
    });

    test('POST /api/notebook updates pages and saves to encrypted storage', async () => {
      const updatedNotebook = {
        title: 'My Notebook Updated',
        coverColor: 'burgundy',
        pages: [
          { id: 'p1', font: 'Georgia', fontSize: '20px', html: '<h2>Chapter 1: The Quest</h2>' },
          { id: 'p2', font: 'Baskerville', fontSize: '18px', html: '<p>A journey begins.</p>' },
        ],
      };

      const res = await fetch(`${server.baseUrl}/api/notebook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ notebook: updatedNotebook }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.notebook.pages.length, 2);
      assert.equal(json.notebook.pages[0].html, '<h2>Chapter 1: The Quest</h2>');
    });

    test('POST /api/notebook can update entire vault atomically', async () => {
      const entireVault = {
        version: 2,
        activeBookId: 'book-custom-1',
        books: [
          {
            id: 'book-custom-1',
            title: 'Atomic Vault Book',
            coverColor: 'black',
            pages: [{ id: 'p-atomic', html: '<p>Atomic write test</p>' }],
          },
        ],
      };

      const res = await fetch(`${server.baseUrl}/api/notebook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ vault: entireVault }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.notebook.title, 'Atomic Vault Book');
    });
  });

  describe('File-Based Image Storage & Session-Gated Serving', () => {
    let uploadedImageUrl = null;
    let imageFilename = null;
    const testBase64Png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

    test('POST /api/images uploads base64 data and writes binary file to disk', async () => {
      const res = await fetch(`${server.baseUrl}/api/images`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({
          data: `data:image/png;base64,${testBase64Png}`,
          ext: 'png',
        }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.ok(json.url.startsWith('/images/'));
      assert.ok(json.url.endsWith('.png'));
      uploadedImageUrl = json.url;
      imageFilename = path.basename(uploadedImageUrl);
    });

    test('POST /api/images fails with 400 when image data is missing', async () => {
      const res = await fetch(`${server.baseUrl}/api/images`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({}),
      });
      assert.equal(res.status, 400);
    });

    test('GET /images/:filename serves binary image bytes with active session', async () => {
      const res = await fetch(`${server.baseUrl}${uploadedImageUrl}`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(res.status, 200);
      const buffer = await res.arrayBuffer();
      const expectedBuffer = Buffer.from(testBase64Png, 'base64');
      assert.deepEqual(Buffer.from(buffer), expectedBuffer);
    });

    test('GET /images/:filename returns 404 for nonexistent files with active session', async () => {
      const res = await fetch(`${server.baseUrl}/images/nonexistent_image_123.jpg`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(res.status, 404);
    });

    test('DELETE /api/images/:filename removes image from storage', async () => {
      const res = await fetch(`${server.baseUrl}/api/images/${imageFilename}`, {
        method: 'DELETE',
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);

      // Verify file is gone
      const verifyRes = await fetch(`${server.baseUrl}${uploadedImageUrl}`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(verifyRes.status, 404);
    });

    test('POST /api/images/upload creates file and returns url and filename', async () => {
      const res = await fetch(`${server.baseUrl}/api/images/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({
          data: `data:image/png;base64,${testBase64Png}`,
          ext: 'png',
        }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.ok(json.url);
      assert.ok(json.filename);

      // Verify GET /api/images/:filename alias serves the image
      const getRes = await fetch(`${server.baseUrl}/api/images/${json.filename}`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(getRes.status, 200);
      const buffer = await getRes.arrayBuffer();
      assert.deepEqual(Buffer.from(buffer), Buffer.from(testBase64Png, 'base64'));

      // Clean up
      await fetch(`${server.baseUrl}/api/images/${json.filename}`, {
        method: 'DELETE',
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
    });

    test('Path traversal attempts on /images/:filename and /api/images/:filename are prevented', async () => {
      const badPaths = [
        '../notebook.enc.json',
        '..%2fnotebook.enc.json',
        'subdir/secret.txt',
        '..\\notebook.enc.json',
      ];
      for (const bad of badPaths) {
        const res = await fetch(`${server.baseUrl}/api/images/${encodeURIComponent(bad)}`, {
          headers: { Cookie: `notebook_session=${sessionCookie}` },
        });
        assert.ok([400, 403, 404].includes(res.status), `Path traversal ${bad} should be blocked (got ${res.status})`);
      }
    });
  });

  describe('Streaming Proxy & Link Preview', () => {
    test('GET /api/proxy returns 400 on missing url parameter', async () => {
      const res = await fetch(`${server.baseUrl}/api/proxy`);
      assert.equal(res.status, 400);
      const json = await res.json();
      assert.equal(json.error, 'Missing url parameter');
    });

    test('GET /api/proxy allows public unauthenticated access (no session cookie required)', async () => {
      const target = `${mockTargetUrl}/preview-page`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(target)}`);
      assert.equal(res.status, 200);
      const body = await res.text();
      assert.ok(body.includes('Hello from Mock Target'));
    });

    test('GET /api/proxy streams HTML, strips X-Frame-Options/CSP, and injects client interceptor', async () => {
      const target = `${mockTargetUrl}/preview-page`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(target)}`);
      assert.equal(res.status, 200);

      // Verify blocking headers are stripped and CORS/XFO headers applied
      assert.equal(res.headers.get('x-frame-options'), 'ALLOWALL');
      assert.equal(res.headers.get('content-security-policy'), null);
      assert.equal(res.headers.get('access-control-allow-origin'), '*');

      const body = await res.text();
      assert.ok(body.includes('_proxyApi'), 'Must inject proxy interception script');
      assert.ok(body.includes('_origOrigin'), 'Must inject origin metadata');
      assert.ok(body.includes('<h1>Hello from Mock Target</h1>'));
    });

    test('GET /api/proxy decompresses gzipped HTML streams cleanly', async () => {
      const target = `${mockTargetUrl}/compressed-page`;
      const res = await fetch(`${server.baseUrl}/api/proxy?url=${encodeURIComponent(target)}`);
      assert.equal(res.status, 200);
      const body = await res.text();
      assert.ok(body.includes('Compressed content'));
      assert.ok(body.includes('_proxyApi'));
    });

    test('GET /api/link-preview allows public unauthenticated access and extracts metadata', async () => {
      const target = `${mockTargetUrl}/preview-page`;
      const res = await fetch(`${server.baseUrl}/api/link-preview?url=${encodeURIComponent(target)}`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.title, 'OG Mock Title');
      assert.equal(json.description, 'OG Mock Description');
      assert.equal(json.domain, '127.0.0.1');
      assert.ok(json.image.includes('test-thumb.jpg'));
    });

    test('OPTIONS /api/proxy-api responds with 200 and permissive CORS headers', async () => {
      const res = await fetch(`${server.baseUrl}/api/proxy-api?url=${encodeURIComponent(mockTargetUrl + '/api/data')}`, {
        method: 'OPTIONS',
      });
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('access-control-allow-origin'), '*');
      assert.ok(res.headers.get('access-control-allow-methods').includes('GET'));
    });

    test('GET /api/proxy-api proxies subresource JSON data publicly without authentication', async () => {
      const res = await fetch(`${server.baseUrl}/api/proxy-api?url=${encodeURIComponent(mockTargetUrl + '/api/data')}`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.status, 'live');
      assert.equal(json.count, 42);
    });

    test('GET /api/proxy-asset proxies subresource assets publicly without authentication', async () => {
      const res = await fetch(`${server.baseUrl}/api/proxy-asset?url=${encodeURIComponent(mockTargetUrl + '/test-thumb.jpg')}`);
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'image/jpeg');
    });
  });

  describe('Password Rotation Lifecycle', () => {
    const newPassword = 'BrandNewSafePassword2026!';

    test('POST /api/change-password rejects short passwords (< 4 chars)', async () => {
      const res = await fetch(`${server.baseUrl}/api/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ newPassword: 'abc' }),
      });
      assert.equal(res.status, 400);
      const json = await res.json();
      assert.ok(json.error.includes('at least 4 characters'));
    });

    test('POST /api/change-password re-encrypts vault and updates session cookie', async () => {
      const res = await fetch(`${server.baseUrl}/api/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ newPassword }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);

      sessionCookie = extractCookie(res);
      assert.ok(sessionCookie);
    });

    test('Unlocking with previous password now fails with 401', async () => {
      // Lock first
      await fetch(`${server.baseUrl}/api/lock`, { method: 'POST' });

      const resOld = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: masterPassword }),
      });
      assert.equal(resOld.status, 401);
    });

    test('Unlocking with new password succeeds and decrypts vault', async () => {
      const resNew = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: newPassword }),
      });
      assert.equal(resNew.status, 200);
      const json = await resNew.json();
      assert.equal(json.ok, true);
      assert.equal(json.notebook.title, 'Atomic Vault Book');
    });
  });

  describe('Enhanced Security & Media/Emoji Capabilities', () => {
    let secServer;
    let secCookie;
    const secPass = 'SecurityMasterKey_2026!';

    before(async () => {
      secServer = await spawnTestServer();
      const setupRes = await fetch(`${secServer.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: secPass }),
      });
      assert.equal(setupRes.status, 200);
      secCookie = extractCookie(setupRes);
    });

    after(async () => {
      if (secServer) await secServer.stop();
    });

    test('GET /api/status returns bookCount before unlocking', async () => {
      // Create 2 additional books
      await fetch(`${secServer.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${secCookie}` },
        body: JSON.stringify({ title: 'Book Two' }),
      });
      await fetch(`${secServer.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${secCookie}` },
        body: JSON.stringify({ title: 'Book Three' }),
      });

      // Lock
      await fetch(`${secServer.baseUrl}/api/lock`, { method: 'POST' });

      // Check status without cookie
      const statusRes = await fetch(`${secServer.baseUrl}/api/status`);
      assert.equal(statusRes.status, 200);
      const statusJson = await statusRes.json();
      assert.equal(statusJson.unlocked, false);
      assert.equal(statusJson.bookCount, 3, 'Status should report 3 books before password entry');
    });

    test('5 consecutive failed password attempts triggers 30-minute lockout (HTTP 429)', async () => {
      for (let i = 1; i <= 4; i++) {
        const failRes = await fetch(`${secServer.baseUrl}/api/unlock`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'BadPassword_' + i }),
        });
        assert.equal(failRes.status, 401);
        const failJson = await failRes.json();
        assert.equal(failJson.attemptsRemaining, 5 - i);
      }

      // 5th failed attempt triggers 429 lockout
      const fifthRes = await fetch(`${secServer.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'BadPassword_5' }),
      });
      assert.equal(fifthRes.status, 429);
      const fifthJson = await fifthRes.json();
      assert.equal(fifthJson.lockedOut, true);
      assert.ok(fifthJson.error.includes('30 minutes'));

      // 6th attempt is rejected by lockout
      const sixthRes = await fetch(`${secServer.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: secPass }),
      });
      assert.equal(sixthRes.status, 429);

      // Verify status reports lockout
      const statusLockRes = await fetch(`${secServer.baseUrl}/api/status`);
      const statusLockJson = await statusLockRes.json();
      assert.equal(statusLockJson.lockedOut, true);
      assert.ok(statusLockJson.remainingSeconds > 0);

      // Unlock with test reset header
      const resetRes = await fetch(`${secServer.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-reset-lockout': '1' },
        body: JSON.stringify({ password: secPass }),
      });
      assert.equal(resetRes.status, 200);
      secCookie = extractCookie(resetRes);
    });

    test('Images are encrypted with AES-256-GCM on disk and served decrypted in-memory', async () => {
      const samplePng = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      const uploadRes = await fetch(`${secServer.baseUrl}/api/images`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${secCookie}` },
        body: JSON.stringify({ data: `data:image/png;base64,${samplePng}`, ext: 'png' }),
      });
      assert.equal(uploadRes.status, 200);
      const uploadJson = await uploadRes.json();
      assert.ok(uploadJson.ok);
      const filename = path.basename(uploadJson.url);

      // Verify file on disk is encrypted with AES-256-GCM (starts with ENC\x01 magic header)
      const diskBytes = fs.readFileSync(path.join(secServer.imagesDir, filename));
      assert.equal(diskBytes.subarray(0, 4).toString('utf8'), 'ENC\x01', 'File on disk must have ENC\x01 encryption header');
      assert.notDeepEqual(diskBytes, Buffer.from(samplePng, 'base64'), 'File on disk must NOT match raw plaintext PNG bytes');

      // Verify GET /images/:filename returns decrypted binary PNG
      const serveRes = await fetch(`${secServer.baseUrl}/images/${filename}`, {
        headers: { Cookie: `notebook_session=${secCookie}` },
      });
      assert.equal(serveRes.status, 200);
      assert.equal(serveRes.headers.get('content-type'), 'image/png');
      const servedBytes = await serveRes.arrayBuffer();
      assert.deepEqual(Buffer.from(servedBytes), Buffer.from(samplePng, 'base64'), 'Served bytes must match original decrypted image');
    });

    test('Supports rich emojis and Unicode across pages and notebook saving', async () => {
      const emojiPage = {
        title: 'Emoji & Unicode Journal 📔',
        pages: [
          {
            id: 'p-emoji-1',
            html: '<p>Exploring the world with emojis! 🚀 ✨ 🔒 📚 🌿 ☕ ❤️ 🔥 🧠 💎</p><p>Multi-byte Unicode: 👨‍💻 👩‍🚀 🏳️‍🌈 日本語 Español</p>',
          },
        ],
      };

      const saveRes = await fetch(`${secServer.baseUrl}/api/notebook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: `notebook_session=${secCookie}` },
        body: JSON.stringify({ notebook: emojiPage }),
      });
      assert.equal(saveRes.status, 200);
      const saveJson = await saveRes.json();
      assert.ok(saveJson.ok);

      // Read back
      const readRes = await fetch(`${secServer.baseUrl}/api/notebook`, {
        headers: { Cookie: `notebook_session=${secCookie}` },
      });
      assert.equal(readRes.status, 200);
      const readJson = await readRes.json();
      assert.ok(readJson.notebook.pages[0].html.includes('🚀 ✨ 🔒 📚 🌿 ☕ ❤️ 🔥 🧠 💎'));
      assert.ok(readJson.notebook.pages[0].html.includes('👨‍💻 👩‍🚀 🏳️‍🌈 日本語 Español'));
    });

    test('POST /api/media/upload supports raw binary video uploads up to 1GB', async () => {
      // Create a 5MB synthetic MP4 video buffer
      const videoBuffer = Buffer.alloc(5 * 1024 * 1024);
      videoBuffer.fill(0x55);
      videoBuffer.write('ftypisom', 4, 'utf8'); // fake MP4 header

      const uploadRes = await fetch(`${secServer.baseUrl}/api/media/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'video/mp4',
          'X-File-Name': 'test_video_large.mp4',
          'X-File-Ext': 'mp4',
          Cookie: `notebook_session=${secCookie}`,
        },
        body: videoBuffer,
      });

      assert.equal(uploadRes.status, 200);
      const uploadJson = await uploadRes.json();
      assert.equal(uploadJson.ok, true);
      assert.equal(uploadJson.isVideo, true);
      assert.equal(uploadJson.ext, 'mp4');
      assert.equal(uploadJson.size, videoBuffer.length);
      assert.ok(uploadJson.url.startsWith('/images/'));

      const filename = path.basename(uploadJson.url);

      // Verify file on disk is encrypted with AES-256-GCM
      const diskBytes = fs.readFileSync(path.join(secServer.imagesDir, filename));
      assert.equal(diskBytes.subarray(0, 4).toString('utf8'), 'ENC\x01');

      // Test HTTP 206 Partial Content / Range header seeking (e.g. bytes=1000-4999)
      const rangeStart = 1000;
      const rangeEnd = 4999;
      const rangeRes = await fetch(`${secServer.baseUrl}/media/${filename}`, {
        headers: {
          Cookie: `notebook_session=${secCookie}`,
          Range: `bytes=${rangeStart}-${rangeEnd}`,
        },
      });

      assert.equal(rangeRes.status, 206, 'Should respond with 206 Partial Content for Range header');
      assert.equal(rangeRes.headers.get('content-range'), `bytes ${rangeStart}-${rangeEnd}/${videoBuffer.length}`);
      assert.equal(rangeRes.headers.get('content-length'), String(rangeEnd - rangeStart + 1));
      assert.equal(rangeRes.headers.get('content-type'), 'video/mp4');
      assert.equal(rangeRes.headers.get('accept-ranges'), 'bytes');

      const chunk = Buffer.from(await rangeRes.arrayBuffer());
      assert.equal(chunk.length, rangeEnd - rangeStart + 1);
      assert.deepEqual(chunk, videoBuffer.subarray(rangeStart, rangeEnd + 1), 'Range bytes must match decrypted slice');
    });

    test('HTTP 206 Partial Content handles open-ended range and out-of-bounds ranges', async () => {
      const audioBuffer = Buffer.alloc(64 * 1024);
      audioBuffer.fill(0xaa);

      const uploadRes = await fetch(`${secServer.baseUrl}/api/media/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'audio/mp3',
          'X-File-Name': 'audio_sample.mp3',
          'X-File-Ext': 'mp3',
          Cookie: `notebook_session=${secCookie}`,
        },
        body: audioBuffer,
      });

      const uploadJson = await uploadRes.json();
      const filename = path.basename(uploadJson.url);

      // Open-ended range (bytes=32768-)
      const openRangeRes = await fetch(`${secServer.baseUrl}/images/${filename}`, {
        headers: {
          Cookie: `notebook_session=${secCookie}`,
          Range: 'bytes=32768-',
        },
      });
      assert.equal(openRangeRes.status, 206);
      assert.equal(openRangeRes.headers.get('content-range'), `bytes 32768-${64 * 1024 - 1}/${64 * 1024}`);

      // Invalid / out-of-bounds range
      const invalidRangeRes = await fetch(`${secServer.baseUrl}/images/${filename}`, {
        headers: {
          Cookie: `notebook_session=${secCookie}`,
          Range: 'bytes=999999-1000000',
        },
      });
      assert.equal(invalidRangeRes.status, 416, 'Out of bounds range must return 416 Range Not Satisfiable');
    });
  });

  describe('Multi-User Support & Public Library Showcase', () => {
    let multiServer;
    const userA = 'alice';
    const passA = 'AlicePassword123!';
    const userB = 'bob';
    const passB = 'BobPassword456!';

    before(async () => {
      multiServer = await spawnTestServer();
    });

    after(async () => {
      if (multiServer) await multiServer.stop();
    });

    test('GET /api/library returns empty/initial list before registration', async () => {
      const res = await fetch(`${multiServer.baseUrl}/api/library`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.ok(Array.isArray(json.notebooks));
      assert.ok(Array.isArray(json.users));
    });

    test('POST /api/users/register creates user Alice with custom title and cover', async () => {
      const res = await fetch(`${multiServer.baseUrl}/api/users/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: userA,
          password: passA,
          notebookTitle: "Alice's Secret Journal",
          coverColor: 'navy',
        }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.user, userA);
      assert.equal(json.notebook.title, "Alice's Secret Journal");
      assert.equal(json.notebook.coverColor, 'navy');
    });

    test('POST /api/users/register creates user Bob with distinct credentials', async () => {
      const res = await fetch(`${multiServer.baseUrl}/api/users/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: userB,
          password: passB,
          notebookTitle: "Bob's Trading Log",
          coverColor: 'green',
        }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.user, userB);
      assert.equal(json.notebook.title, "Bob's Trading Log");
      assert.equal(json.notebook.coverColor, 'green');
    });

    test('GET /api/library lists notebooks from both Alice and Bob', async () => {
      const res = await fetch(`${multiServer.baseUrl}/api/library`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.ok(json.notebooks.length >= 2);
      const aliceBook = json.notebooks.find((b) => b.owner === userA);
      const bobBook = json.notebooks.find((b) => b.owner === userB);
      assert.ok(aliceBook, 'Alice notebook should be in public library');
      assert.equal(aliceBook.title, "Alice's Secret Journal");
      assert.equal(aliceBook.coverColor, 'navy');
      assert.ok(bobBook, 'Bob notebook should be in public library');
      assert.equal(bobBook.title, "Bob's Trading Log");
      assert.equal(bobBook.coverColor, 'green');
    });

    test('User login verifies credentials and isolates vaults', async () => {
      // Bob tries to login with Alice password -> fails
      const badLogin = await fetch(`${multiServer.baseUrl}/api/users/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: userB, password: passA }),
      });
      assert.equal(badLogin.status, 401);

      // Alice logs in with correct password -> succeeds
      const aliceLogin = await fetch(`${multiServer.baseUrl}/api/users/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: userA, password: passA }),
      });
      assert.equal(aliceLogin.status, 200);
      const aliceJson = await aliceLogin.json();
      assert.equal(aliceJson.user, userA);
      assert.equal(aliceJson.notebook.title, "Alice's Secret Journal");
    });
  });
});
