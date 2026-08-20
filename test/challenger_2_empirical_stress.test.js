const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const net = require('node:net');
const { spawnTestServer, extractCookie, getFreePort, createSandbox } = require('./test_helper.js');

// Crypto helpers matching server.js
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

// Raw HTTP helper for testing low-level wire formats that bypass URL client normalization
function sendRawHttpRequest(port, rawHttpString) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection({ port, host: '127.0.0.1' }, () => {
      client.write(rawHttpString);
    });
    let responseData = '';
    client.on('data', (chunk) => {
      responseData += chunk.toString();
    });
    client.on('end', () => {
      const statusLine = responseData.split('\r\n')[0] || '';
      const match = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
      const statusCode = match ? parseInt(match[1], 10) : null;
      resolve({ statusCode, raw: responseData });
    });
    client.on('error', reject);
  });
}

describe('Challenger 2: Empirical Stress Test Harness', () => {

  // =========================================================================
  // STRESS AREA 1: Serverless Compatibility & Stateless Multi-Instance
  // =========================================================================
  describe('Area 1: Serverless Compatibility & Multi-Instance State Sharing', () => {
    let serverlessInstanceA;
    let serverlessInstanceB;
    let sessionCookie;
    const password = 'ServerlessMasterPassword2026!';
    const sharedSecret = 'test-serverless-shared-secret-key-12345';
    const vercelDataDir = path.join('/tmp', 'data');

    before(async () => {
      try {
        if (fs.existsSync(vercelDataDir)) {
          fs.rmSync(vercelDataDir, { recursive: true, force: true });
        }
      } catch (e) {}

      // Instance A boots with VERCEL=1 and shared SESSION_SECRET
      serverlessInstanceA = await spawnTestServer({
        isVercel: true,
        envOverrides: { SESSION_SECRET: sharedSecret },
      });

      // Instance A performs setup
      const setupRes = await fetch(`${serverlessInstanceA.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(setupRes.status, 200);
      sessionCookie = extractCookie(setupRes);
      assert.ok(sessionCookie, 'Session cookie must be issued on setup');

      // Instance B boots independently with VERCEL=1 and same SESSION_SECRET
      serverlessInstanceB = await spawnTestServer({
        isVercel: true,
        envOverrides: { SESSION_SECRET: sharedSecret },
      });
    });

    after(async () => {
      if (serverlessInstanceA) await serverlessInstanceA.stop();
      if (serverlessInstanceB) await serverlessInstanceB.stop();
      try {
        if (fs.existsSync(vercelDataDir)) {
          fs.rmSync(vercelDataDir, { recursive: true, force: true });
        }
      } catch (e) {}
    });

    test('1.1: Serverless Instance B decrypts vault using session cookie from Instance A without unlock', async () => {
      const getRes = await fetch(`${serverlessInstanceB.baseUrl}/api/notebook`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(getRes.status, 200);
      const getJson = await getRes.json();
      assert.equal(getJson.ok, true);
      assert.equal(getJson.vault.version, 2);
      assert.equal(getJson.notebook.title, 'My Notebook');
    });

    test('1.2: Serverless Instance B creates a new notebook and Instance A reads it seamlessly', async () => {
      const createRes = await fetch(`${serverlessInstanceB.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({ title: 'Serverless Chronicles', coverColor: 'emerald' }),
      });
      assert.equal(createRes.status, 200);
      const createJson = await createRes.json();
      assert.equal(createJson.ok, true);
      const newBookId = createJson.activeBookId;

      // Instance A reads library
      const listRes = await fetch(`${serverlessInstanceA.baseUrl}/api/books`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(listRes.status, 200);
      const listJson = await listRes.json();
      assert.equal(listJson.activeBookId, newBookId);
      assert.ok(listJson.books.some((b) => b.title === 'Serverless Chronicles'));
    });

    test('1.3: Serverless cookie includes SameSite=None and Secure attributes', async () => {
      const unlockRes = await fetch(`${serverlessInstanceA.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(unlockRes.status, 200);
      const rawCookie = unlockRes.headers.get('set-cookie');
      assert.ok(rawCookie.includes('SameSite=None'), 'Must contain SameSite=None');
      assert.ok(rawCookie.includes('Secure'), 'Must contain Secure flag');
      assert.ok(rawCookie.includes('HttpOnly'), 'Must contain HttpOnly');
    });
  });

  // =========================================================================
  // STRESS AREA 2: Stateless Cookie Auth Token Security & Cryptographic Integrity
  // =========================================================================
  describe('Area 2: Stateless Cookie Auth Token Security & Cryptographic Integrity', () => {
    let server;
    let validCookie;
    const password = 'CookieTamperStressPassword2026!';

    before(async () => {
      server = await spawnTestServer();
      const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(setupRes.status, 200);
      validCookie = extractCookie(setupRes);
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('2.1: Tampered IV in session token is rejected with 401', async () => {
      const decoded = decodeURIComponent(validCookie);
      const parts = decoded.split('.');
      assert.equal(parts.length, 3);
      // Flip bits in IV
      const tamperedIv = (parseInt(parts[0].slice(0, 2), 16) ^ 0xff).toString(16).padStart(2, '0') + parts[0].slice(2);
      const tamperedCookie = encodeURIComponent(`${tamperedIv}.${parts[1]}.${parts[2]}`);

      const res = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { Cookie: `notebook_session=${tamperedCookie}` },
      });
      assert.equal(res.status, 401);
      const json = await res.json();
      assert.equal(json.error, 'Notebook is locked.');
    });

    test('2.2: Tampered authTag in session token is rejected with 401', async () => {
      const decoded = decodeURIComponent(validCookie);
      const parts = decoded.split('.');
      const tamperedTag = (parseInt(parts[1].slice(0, 2), 16) ^ 0xff).toString(16).padStart(2, '0') + parts[1].slice(2);
      const tamperedCookie = encodeURIComponent(`${parts[0]}.${tamperedTag}.${parts[2]}`);

      const res = await fetch(`${server.baseUrl}/api/books`, {
        headers: { Cookie: `notebook_session=${tamperedCookie}` },
      });
      assert.equal(res.status, 401);
    });

    test('2.3: Tampered ciphertext payload in session token is rejected with 401', async () => {
      const decoded = decodeURIComponent(validCookie);
      const parts = decoded.split('.');
      const tamperedData = (parseInt(parts[2].slice(0, 2), 16) ^ 0xff).toString(16).padStart(2, '0') + parts[2].slice(2);
      const tamperedCookie = encodeURIComponent(`${parts[0]}.${parts[1]}.${tamperedData}`);

      const res = await fetch(`${server.baseUrl}/api/books`, {
        headers: { Cookie: `notebook_session=${tamperedCookie}` },
      });
      assert.equal(res.status, 401);
    });

    test('2.4: Truncated, malformed, and injection tokens are rejected with 401', async () => {
      const maliciousTokens = [
        'invalid-format',
        'a.b',
        'a.b.c.d',
        '..',
        'null',
        'undefined',
        '00'.repeat(100),
        '%00%00',
        '<script>alert(1)</script>',
        '{"token": "fake"}',
      ];

      for (const token of maliciousTokens) {
        const res = await fetch(`${server.baseUrl}/api/notebook`, {
          headers: { Cookie: `notebook_session=${encodeURIComponent(token)}` },
        });
        assert.equal(res.status, 401, `Token "${token}" must be rejected with 401`);
      }
    });

    test('2.5: POST /api/lock clears session cookie and revokes access immediately', async () => {
      const lockRes = await fetch(`${server.baseUrl}/api/lock`, {
        method: 'POST',
        headers: { Cookie: `notebook_session=${validCookie}` },
      });
      assert.equal(lockRes.status, 200);
      const setCookie = lockRes.headers.get('set-cookie');
      assert.ok(setCookie.includes('Max-Age=0'));

      const postLockRes = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { Cookie: 'notebook_session=' },
      });
      assert.equal(postLockRes.status, 401);
    });
  });

  // =========================================================================
  // STRESS AREA 3: Unauthenticated Public Endpoints vs Gated Endpoints Matrix
  // =========================================================================
  describe('Area 3: Unauthenticated Public Endpoints vs Strict Gated Matrix', () => {
    let server;
    let validCookie;
    let testImageFile;
    const password = 'PublicEndpointMatrixPassword2026!';

    before(async () => {
      server = await spawnTestServer();
      const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(setupRes.status, 200);
      validCookie = extractCookie(setupRes);

      // Upload a test image
      const imgUploadRes = await fetch(`${server.baseUrl}/api/images/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${validCookie}`,
        },
        body: JSON.stringify({
          data: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
          ext: 'png',
        }),
      });
      assert.equal(imgUploadRes.status, 200);
      const imgJson = await imgUploadRes.json();
      testImageFile = imgJson.filename;
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('3.1: Public unauthenticated endpoints accept anonymous requests', async () => {
      // 1. /api/status
      const statusRes = await fetch(`${server.baseUrl}/api/status`);
      assert.equal(statusRes.status, 200);
      const statusJson = await statusRes.json();
      assert.equal(statusJson.setupNeeded, false);
      assert.equal(statusJson.unlocked, false);

      // 2. /api/search
      const searchRes = await fetch(`${server.baseUrl}/api/search?q=test`);
      assert.equal(searchRes.status, 200);
      const searchJson = await searchRes.json();
      assert.equal(searchJson.ok, true);

      // 3. /api/link-preview (empty or malformed url returns 400, not 401)
      const previewRes = await fetch(`${server.baseUrl}/api/link-preview`);
      assert.equal(previewRes.status, 400);

      // 4. /api/proxy (empty url returns 400, not 401)
      const proxyRes = await fetch(`${server.baseUrl}/api/proxy`);
      assert.equal(proxyRes.status, 400);

      // 5. /api/proxy-api OPTIONS
      const optionsRes = await fetch(`${server.baseUrl}/api/proxy-api`, { method: 'OPTIONS' });
      assert.equal(optionsRes.status, 200);
      assert.equal(optionsRes.headers.get('access-control-allow-origin'), '*');
    });

    test('3.2: Gated endpoints strictly reject all unauthenticated requests with 401', async () => {
      const gatedEndpoints = [
        { method: 'GET', url: '/api/notebook' },
        { method: 'POST', url: '/api/notebook', body: { notebook: {} } },
        { method: 'POST', url: '/api/save', body: { notebook: {} } },
        { method: 'GET', url: '/api/books' },
        { method: 'POST', url: '/api/books/create', body: { title: 'X' } },
        { method: 'POST', url: '/api/books/switch', body: { bookId: 'x' } },
        { method: 'POST', url: '/api/books/rename', body: { bookId: 'x', title: 'Y' } },
        { method: 'PUT', url: '/api/books/x', body: { title: 'Y' } },
        { method: 'POST', url: '/api/books/delete', body: { bookId: 'x' } },
        { method: 'DELETE', url: '/api/books/x' },
        { method: 'POST', url: '/api/change-password', body: { newPassword: 'pass' } },
        { method: 'POST', url: '/api/images', body: { data: 'abc' } },
        { method: 'POST', url: '/api/images/upload', body: { data: 'abc' } },
        { method: 'GET', url: `/images/${testImageFile}` },
        { method: 'GET', url: `/api/images/${testImageFile}` },
        { method: 'DELETE', url: `/images/${testImageFile}` },
        { method: 'DELETE', url: `/api/images/${testImageFile}` },
      ];

      for (const ep of gatedEndpoints) {
        const opts = { method: ep.method };
        if (ep.body) {
          opts.headers = { 'Content-Type': 'application/json' };
          opts.body = JSON.stringify(ep.body);
        }
        const res = await fetch(`${server.baseUrl}${ep.url}`, opts);
        assert.equal(res.status, 401, `Gated endpoint ${ep.method} ${ep.url} MUST return 401 when unauthenticated, got ${res.status}`);
      }
    });
  });

  // =========================================================================
  // STRESS AREA 4: Path-Traversal Resilience in Image Routes
  // =========================================================================
  describe('Area 4: Path-Traversal Resilience in Image Routes', () => {
    let server;
    let cookie;
    let sampleFilename;
    const password = 'PathTraversalPassword2026!';

    before(async () => {
      server = await spawnTestServer();
      const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(setupRes.status, 200);
      cookie = extractCookie(setupRes);

      // Upload valid image
      const upRes = await fetch(`${server.baseUrl}/api/images/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${cookie}`,
        },
        body: JSON.stringify({
          data: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
          ext: 'png',
        }),
      });
      assert.equal(upRes.status, 200);
      const json = await upRes.json();
      sampleFilename = json.filename;
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('4.1: Path traversal attempts on /images/:filename and /api/images/:filename are strictly blocked', async () => {
      const maliciousPayloads = [
        '..%2fserver.js',
        '..%5cserver.js',
        '%252e%252e%252fserver.js',
        '..%2f..%2fpackage.json',
        'image.png%00.js',
        'image.png;rm -rf /',
        '`whoami`',
        'foo%00bar.png',
        'sub/dir/img.png',
        '..\\server.js',
        '../../etc/passwd',
      ];

      for (const attack of maliciousPayloads) {
        // Test GET /api/images/:filename
        const res1 = await fetch(`${server.baseUrl}/api/images/${attack}`, {
          headers: { Cookie: `notebook_session=${cookie}` },
        });
        assert.ok(
          [400, 403, 404].includes(res1.status),
          `GET /api/images/${attack} must be blocked (got ${res1.status})`
        );

        // Test DELETE /api/images/:filename
        const res2 = await fetch(`${server.baseUrl}/api/images/${attack}`, {
          method: 'DELETE',
          headers: { Cookie: `notebook_session=${cookie}` },
        });
        assert.ok(
          [400, 403, 404].includes(res2.status),
          `DELETE /api/images/${attack} must be blocked (got ${res2.status})`
        );
      }
    });

    test('4.2: Raw wire-level HTTP path traversal payloads are rejected by server', async () => {
      const rawWireRequests = [
        `GET /images/../server.js HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nCookie: notebook_session=${cookie}\r\n\r\n`,
        `GET /images/../../package.json HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nCookie: notebook_session=${cookie}\r\n\r\n`,
        `GET /api/images/../server.js HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nCookie: notebook_session=${cookie}\r\n\r\n`,
      ];

      for (const reqStr of rawWireRequests) {
        const rawRes = await sendRawHttpRequest(server.port, reqStr);
        assert.ok(
          [400, 403, 404].includes(rawRes.statusCode),
          `Raw request must be blocked, got status ${rawRes.statusCode}`
        );
      }
    });

    test('4.3: Valid image filename is served properly without false positive blocks', async () => {
      const validRes = await fetch(`${server.baseUrl}/api/images/${sampleFilename}`, {
        headers: { Cookie: `notebook_session=${cookie}` },
      });
      assert.equal(validRes.status, 200);
      const buffer = await validRes.arrayBuffer();
      assert.ok(buffer.byteLength > 0);
    });
  });

  // =========================================================================
  // STRESS AREA 5: Multi-Book Schema Migration & Backward Compatibility
  // =========================================================================
  describe('Area 5: Multi-Book Schema Migration & Legacy Vault Upgrade', () => {
    let server;
    const legacyPassword = 'LegacyVaultPassword2026!';
    const salt = crypto.randomBytes(16).toString('hex');
    const key = deriveKey(legacyPassword, salt);

    const legacySingleBookVault = {
      title: 'Captain Ancient Diary',
      coverColor: 'burgundy',
      createdAt: '2023-01-01T00:00:00.000Z',
      updatedAt: '2023-01-02T00:00:00.000Z',
      pages: [
        {
          id: 'p-old-1',
          font: 'Georgia',
          fontSize: '18px',
          html: '<h1>Page 1</h1><p>Old entry with <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="> embedded.</p>',
        },
        {
          id: 'p-old-2',
          font: 'Georgia',
          fontSize: '18px',
          html: '<h1>Page 2</h1><p>Second page notes.</p>',
        },
      ],
    };

    const encryptedLegacyPayload = {
      salt,
      ...encryptData(legacySingleBookVault, key),
    };

    before(async () => {
      server = await spawnTestServer({ initialVault: encryptedLegacyPayload });
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('5.1: Unlocking legacy single-book vault normalizes to v2 multi-book envelope with zero data loss', async () => {
      const unlockRes = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: legacyPassword }),
      });
      assert.equal(unlockRes.status, 200);
      const json = await unlockRes.json();
      assert.equal(json.ok, true);
      assert.equal(json.vault.version, 2);
      assert.equal(json.vault.books.length, 1);
      assert.equal(json.vault.books[0].title, 'Captain Ancient Diary');
      assert.equal(json.vault.books[0].coverColor, 'burgundy');
      assert.equal(json.vault.books[0].pages.length, 2);

      // Base64 image must have been extracted and migrated
      assert.ok(!json.vault.books[0].pages[0].html.includes('data:image/png;base64'));
      assert.ok(json.vault.books[0].pages[0].html.includes('src="/images/'));

      const cookie = extractCookie(unlockRes);

      // Books endpoint reflects migrated structure
      const booksRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { Cookie: `notebook_session=${cookie}` },
      });
      assert.equal(booksRes.status, 200);
      const booksJson = await booksRes.json();
      assert.equal(booksJson.books.length, 1);
      assert.equal(booksJson.books[0].title, 'Captain Ancient Diary');
      assert.equal(booksJson.books[0].pageCount, 2);
    });

    test('5.2: Multi-book CRUD operates smoothly after migration', async () => {
      const unlockRes = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: legacyPassword }),
      });
      const cookie = extractCookie(unlockRes);

      // Create second book
      const createRes = await fetch(`${server.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${cookie}`,
        },
        body: JSON.stringify({ title: 'Modern Voyages', coverColor: 'navy' }),
      });
      assert.equal(createRes.status, 200);
      const createJson = await createRes.json();
      assert.equal(createJson.vault.books.length, 2);

      // Delete the original migrated book
      const origBookId = createJson.vault.books.find((b) => b.title === 'Captain Ancient Diary').id;
      const delRes = await fetch(`${server.baseUrl}/api/books/${origBookId}`, {
        method: 'DELETE',
        headers: { Cookie: `notebook_session=${cookie}` },
      });
      assert.equal(delRes.status, 200);
      const delJson = await delRes.json();
      assert.equal(delJson.vault.books.length, 1);
      assert.equal(delJson.vault.books[0].title, 'Modern Voyages');
    });
  });

});
