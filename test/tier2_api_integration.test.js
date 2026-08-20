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
        { path: '/api/proxy-asset?url=http://example.com', method: 'GET' },
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
});
