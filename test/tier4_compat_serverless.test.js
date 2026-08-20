const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnTestServer, extractCookie, getFreePort, createSandbox } = require('./test_helper.js');

// Crypto helpers matching server.js for synthesizing test fixtures
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

describe('Tier 4: Compatibility & Serverless Tests', () => {

  describe('Legacy Vault Migration (v1 Single-Book to v2 Envelope)', () => {
    let server;
    const password = 'LegacyPassword2024!';
    const salt = crypto.randomBytes(16).toString('hex');
    const key = deriveKey(password, salt);

    const legacyV1Vault = {
      title: 'Captain\'s Log 2023',
      coverColor: 'navy',
      createdAt: '2023-05-10T08:00:00.000Z',
      updatedAt: '2023-05-11T09:30:00.000Z',
      pages: [
        {
          id: 'page-entry-1',
          font: "Palatino, 'Palatino Linotype', Georgia, serif",
          fontSize: '20px',
          html: '<h1>Day 1</h1><p>We set sail from Portsmouth at dawn.</p>',
        },
        {
          id: 'page-entry-2',
          font: "Georgia, 'Times New Roman', serif",
          fontSize: '18px',
          html: '<h2>Day 2</h2><p>Calm waters and clear skies.</p>',
        },
      ],
    };

    const encryptedPayload = {
      version: 1,
      salt,
      ...encryptData(legacyV1Vault, key),
    };

    before(async () => {
      server = await spawnTestServer({ initialVault: encryptedPayload });
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('unlocks legacy v1 vault without errors and normalizes to v2 schema', async () => {
      const res = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);

      // Verify v2 envelope
      assert.equal(json.vault.version, 2);
      assert.equal(json.vault.books.length, 1);
      assert.equal(json.vault.activeBookId, 'book-default');

      // Verify notebook metadata preserved
      assert.equal(json.notebook.title, 'Captain\'s Log 2023');
      assert.equal(json.notebook.coverColor, 'navy');
      assert.equal(json.notebook.createdAt, '2023-05-10T08:00:00.000Z');
      assert.equal(json.notebook.updatedAt, '2023-05-11T09:30:00.000Z');

      // Verify all pages preserved without data loss
      assert.equal(json.notebook.pages.length, 2);
      assert.equal(json.notebook.pages[0].id, 'page-entry-1');
      assert.equal(json.notebook.pages[0].html, '<h1>Day 1</h1><p>We set sail from Portsmouth at dawn.</p>');
      assert.equal(json.notebook.pages[1].id, 'page-entry-2');
      assert.equal(json.notebook.pages[1].html, '<h2>Day 2</h2><p>Calm waters and clear skies.</p>');
    });

    test('subsequent /api/books and /api/notebook calls return migrated v2 structure', async () => {
      // Re-unlock to obtain fresh session cookie
      const unlockRes = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const cookie = extractCookie(unlockRes);

      const booksRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { Cookie: `notebook_session=${cookie}` },
      });
      assert.equal(booksRes.status, 200);
      const booksJson = await booksRes.json();
      assert.equal(booksJson.books.length, 1);
      assert.equal(booksJson.books[0].title, 'Captain\'s Log 2023');
      assert.equal(booksJson.books[0].pageCount, 2);

      const notebookRes = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { Cookie: `notebook_session=${cookie}` },
      });
      assert.equal(notebookRes.status, 200);
      const notebookJson = await notebookRes.json();
      assert.equal(notebookJson.vault.version, 2);
      assert.equal(notebookJson.notebook.title, 'Captain\'s Log 2023');
    });

    test('recovers legacy vault with missing pages by creating default page', async () => {
      const minimalLegacy = {
        title: 'Minimal Book',
        coverColor: 'green',
      };
      const minSalt = crypto.randomBytes(16).toString('hex');
      const minKey = deriveKey('minPass123', minSalt);
      const minEncrypted = {
        version: 1,
        salt: minSalt,
        ...encryptData(minimalLegacy, minKey),
      };

      const minServer = await spawnTestServer({ initialVault: minEncrypted });
      try {
        const res = await fetch(`${minServer.baseUrl}/api/unlock`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'minPass123' }),
        });
        assert.equal(res.status, 200);
        const json = await res.json();
        assert.equal(json.ok, true);
        assert.equal(json.notebook.title, 'Minimal Book');
        assert.equal(json.notebook.pages.length, 1);
        assert.ok(json.notebook.pages[0].id.startsWith('p-'));
      } finally {
        await minServer.stop();
      }
    });
  });

  describe('Base64 Inline Image Extraction & Auto-Migration', () => {
    let server;
    const password = 'Base64MigrationPass!';
    const salt = crypto.randomBytes(16).toString('hex');
    const key = deriveKey(password, salt);

    const samplePngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    const sampleJpgBase64 = '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=';
    const sampleWebpBase64 = 'UklGRhoAAABXRUJQVlA4TA0AAAAvAAAAEAcQERGIiP4HAA==';

    const vaultWithBase64 = {
      version: 2,
      activeBookId: 'book-b64',
      books: [
        {
          id: 'book-b64',
          title: 'Illustrated Memoirs',
          coverColor: 'burgundy',
          pages: [
            {
              id: 'p-img-1',
              font: 'Georgia',
              fontSize: '18px',
              html: `<p>First sketch:</p><img class="vintage" src="data:image/png;base64,${samplePngBase64}" alt="pixel"><p>Second sketch:</p><img src="data:image/jpeg;base64,${sampleJpgBase64}"><p>Webp sketch:</p><img src="data:image/webp;base64,${sampleWebpBase64}">`,
            },
            {
              id: 'p-img-2',
              font: 'Georgia',
              fontSize: '18px',
              html: `<p>Already migrated:</p><img src="/images/existing_asset.png"><img src="https://example.com/remote.jpg">`,
            },
          ],
        },
      ],
    };

    const encryptedPayload = {
      version: 2,
      salt,
      ...encryptData(vaultWithBase64, key),
    };

    before(async () => {
      server = await spawnTestServer({ initialVault: encryptedPayload });
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('migrates inline base64 images into physical files and rewrites HTML on unlock', async () => {
      const res = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);

      const page1Html = json.notebook.pages[0].html;

      // Verify inline base64 was removed
      assert.ok(!page1Html.includes('data:image/png;base64'));
      assert.ok(!page1Html.includes('data:image/jpeg;base64'));
      assert.ok(!page1Html.includes('data:image/webp;base64'));

      // Verify replaced with /images/<filename> URLs
      assert.ok(page1Html.includes('class="vintage" src="/images/'));
      assert.ok(page1Html.includes('alt="pixel"'));

      // Verify physical image files exist in imagesDir
      const filesOnDisk = fs.readdirSync(server.imagesDir);
      assert.equal(filesOnDisk.length, 3);
      assert.ok(filesOnDisk.some((f) => f.endsWith('.png')));
      assert.ok(filesOnDisk.some((f) => f.endsWith('.jpeg') || f.endsWith('.jpg')));
      assert.ok(filesOnDisk.some((f) => f.endsWith('.webp')));

      // Verify file contents match original binary data
      const pngFile = filesOnDisk.find((f) => f.endsWith('.png'));
      const pngBuffer = fs.readFileSync(path.join(server.imagesDir, pngFile));
      assert.deepEqual(pngBuffer, Buffer.from(samplePngBase64, 'base64'));

      const cookie = extractCookie(res);
      // Verify served via session-gated image endpoint
      const imgRes = await fetch(`${server.baseUrl}/images/${pngFile}`, {
        headers: { Cookie: `notebook_session=${cookie}` },
      });
      assert.equal(imgRes.status, 200);
      const imgBytes = await imgRes.arrayBuffer();
      assert.deepEqual(Buffer.from(imgBytes), Buffer.from(samplePngBase64, 'base64'));
    });

    test('preserves existing /images/ and external URLs without re-migrating', async () => {
      const unlockRes = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const json = await unlockRes.json();
      const page2Html = json.notebook.pages[1].html;
      assert.ok(page2Html.includes('src="/images/existing_asset.png"'));
      assert.ok(page2Html.includes('src="https://example.com/remote.jpg"'));
    });

    test('re-encrypted file on disk contains migrated /images/ references', () => {
      const diskData = JSON.parse(fs.readFileSync(path.join(server.dataDir, 'notebook.enc.json'), 'utf8'));
      const decrypted = decryptData(diskData, key);
      const diskHtml = decrypted.books[0].pages[0].html;
      assert.ok(!diskHtml.includes('data:image/'));
      assert.ok(diskHtml.includes('/images/'));
    });
  });

  describe('Vercel Serverless Environment Bootstrap', () => {
    let vercelServer;
    const vercelDataDir = path.join('/tmp', 'data');

    before(async () => {
      try {
        if (fs.existsSync(vercelDataDir)) {
          fs.rmSync(vercelDataDir, { recursive: true, force: true });
        }
      } catch (e) {}
      vercelServer = await spawnTestServer({ isVercel: true });
    });

    after(async () => {
      if (vercelServer) await vercelServer.stop();
      try {
        if (fs.existsSync(vercelDataDir)) {
          fs.rmSync(vercelDataDir, { recursive: true, force: true });
        }
      } catch (e) {}
    });

    test('boots successfully under process.env.VERCEL=1', async () => {
      const res = await fetch(`${vercelServer.baseUrl}/api/status`);
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.setupNeeded, true);
      assert.equal(json.unlocked, false);
    });

    test('performs setup and writes data under Vercel environment', async () => {
      const res = await fetch(`${vercelServer.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'VercelMasterKey123' }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.notebook.title, 'My Notebook');
    });

    test('uses SameSite=None; Secure cookie flags in Vercel serverless mode', async () => {
      const res = await fetch(`${vercelServer.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'VercelMasterKey123' }),
      });
      assert.equal(res.status, 200);

      const setCookie = res.headers.get('set-cookie');
      assert.ok(setCookie, 'Set-Cookie header must be present');
      assert.ok(setCookie.includes('SameSite=None'), 'Must contain SameSite=None on Vercel');
      assert.ok(setCookie.includes('Secure'), 'Must contain Secure flag on Vercel');
      assert.ok(setCookie.includes('HttpOnly'), 'Must contain HttpOnly flag');
      assert.ok(setCookie.includes('Path=/'), 'Must contain Path=/');
      assert.ok(setCookie.includes('Max-Age=2592000'), 'Must contain Max-Age');
    });

    test('supports multi-book operations in Vercel mode', async () => {
      const unlockRes = await fetch(`${vercelServer.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'VercelMasterKey123' }),
      });
      const cookie = extractCookie(unlockRes);

      const createRes = await fetch(`${vercelServer.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${cookie}`,
        },
        body: JSON.stringify({
          title: 'Vercel Serverless Notes',
          coverColor: 'navy',
        }),
      });
      assert.equal(createRes.status, 200);
      const createJson = await createRes.json();
      assert.equal(createJson.ok, true);
      assert.equal(createJson.notebook.title, 'Vercel Serverless Notes');
    });
  });

  describe('Stateless Multi-Instance Serverless Continuity', () => {
    let instanceA;
    let instanceB;
    let sessionCookie;
    const sessionSecret = 'shared-secret-for-multi-instance-test-2026';
    const password = 'MultiInstanceVaultPass123!';

    before(async () => {
      // Create a shared sandbox directory so both instances see the same data folder
      const { tmpDir, dataDir, imagesDir, appRoot } = createSandbox();
      const portA = await getFreePort();
      const portB = await getFreePort();

      const nodeModulesPath = path.join(appRoot, 'node_modules');
      const envA = {
        ...process.env,
        PORT: String(portA),
        NODE_PATH: nodeModulesPath,
        SESSION_SECRET: sessionSecret,
      };
      const envB = {
        ...process.env,
        PORT: String(portB),
        NODE_PATH: nodeModulesPath,
        SESSION_SECRET: sessionSecret,
      };

      // Spawn Instance A
      const procA = require('child_process').spawn(process.execPath, ['server.js'], {
        cwd: tmpDir,
        env: envA,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      // Spawn Instance B
      const procB = require('child_process').spawn(process.execPath, ['server.js'], {
        cwd: tmpDir,
        env: envB,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const baseUrlA = `http://127.0.0.1:${portA}`;
      const baseUrlB = `http://127.0.0.1:${portB}`;

      // Wait for both to be ready
      for (let i = 0; i < 50; i++) {
        try {
          const [resA, resB] = await Promise.all([
            fetch(`${baseUrlA}/api/status`),
            fetch(`${baseUrlB}/api/status`),
          ]);
          if (resA.ok && resB.ok) break;
        } catch (e) {
          await new Promise((r) => setTimeout(r, 80));
        }
      }

      instanceA = {
        baseUrl: baseUrlA,
        proc: procA,
        tmpDir,
      };
      instanceB = {
        baseUrl: baseUrlB,
        proc: procB,
        tmpDir,
      };
    });

    after(async () => {
      if (instanceA && instanceA.proc) instanceA.proc.kill();
      if (instanceB && instanceB.proc) instanceB.proc.kill();
      if (instanceA && instanceA.tmpDir) {
        try { fs.rmSync(instanceA.tmpDir, { recursive: true, force: true }); } catch (e) {}
      }
    });

    test('Instance A sets up the vault and issues stateless encrypted session cookie', async () => {
      const res = await fetch(`${instanceA.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);

      sessionCookie = extractCookie(res);
      assert.ok(sessionCookie);
    });

    test('Instance B immediately reads notebook using Instance A session cookie without prior unlock', async () => {
      // Instance B has never had /api/unlock called and has null in-memory sessionKey
      const res = await fetch(`${instanceB.baseUrl}/api/notebook`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(res.status, 200);
      const json = await res.json();
      assert.equal(json.ok, true);
      assert.equal(json.notebook.title, 'My Notebook');
    });

    test('Instance B creates a new notebook and Instance A reads the updated vault', async () => {
      // Create book on Instance B
      const createRes = await fetch(`${instanceB.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `notebook_session=${sessionCookie}`,
        },
        body: JSON.stringify({
          title: 'Cross-Instance Grimoire',
          coverColor: 'green',
        }),
      });
      assert.equal(createRes.status, 200);
      const createJson = await createRes.json();
      assert.equal(createJson.ok, true);
      assert.equal(createJson.vault.books.length, 2);

      // Read books listing from Instance A
      const listRes = await fetch(`${instanceA.baseUrl}/api/books`, {
        headers: { Cookie: `notebook_session=${sessionCookie}` },
      });
      assert.equal(listRes.status, 200);
      const listJson = await listRes.json();
      assert.equal(listJson.books.length, 2);
      assert.ok(listJson.books.some((b) => b.title === 'Cross-Instance Grimoire'));
    });

    test('Instance with different SESSION_SECRET rejects session cookie (isolation)', async () => {
      const portC = await getFreePort();
      const procC = require('child_process').spawn(process.execPath, ['server.js'], {
        cwd: instanceA.tmpDir,
        env: {
          ...process.env,
          PORT: String(portC),
          NODE_PATH: path.join(path.resolve(__dirname, '..'), 'node_modules'),
          SESSION_SECRET: 'completely-different-secret-777',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const baseUrlC = `http://127.0.0.1:${portC}`;
      for (let i = 0; i < 50; i++) {
        try {
          const res = await fetch(`${baseUrlC}/api/status`);
          if (res.ok) break;
        } catch (e) {
          await new Promise((r) => setTimeout(r, 80));
        }
      }

      try {
        const res = await fetch(`${baseUrlC}/api/notebook`, {
          headers: { Cookie: `notebook_session=${sessionCookie}` },
        });
        assert.equal(res.status, 401, 'Should reject cookie encrypted with different secret');
      } finally {
        procC.kill();
      }
    });
  });

  describe('Cookie Security Attributes & Lifecycle', () => {
    let localServer;

    before(async () => {
      localServer = await spawnTestServer({ isVercel: false });
    });

    after(async () => {
      if (localServer) await localServer.stop();
    });

    test('uses SameSite=Lax and HttpOnly in local development execution', async () => {
      const setupRes = await fetch(`${localServer.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'LocalSafePass123' }),
      });
      assert.equal(setupRes.status, 200);
      const setCookie = setupRes.headers.get('set-cookie');
      assert.ok(setCookie.includes('SameSite=Lax'));
      assert.ok(setCookie.includes('HttpOnly'));
      assert.ok(setCookie.includes('Path=/'));
      assert.ok(!setCookie.includes('Secure')); // Secure omitted on plain HTTP local
    });

    test('POST /api/lock clears cookie with Max-Age=0 in all environments', async () => {
      const lockRes = await fetch(`${localServer.baseUrl}/api/lock`, {
        method: 'POST',
      });
      assert.equal(lockRes.status, 200);
      const setCookie = lockRes.headers.get('set-cookie');
      assert.ok(setCookie.includes('notebook_session=;'));
      assert.ok(setCookie.includes('Max-Age=0'));
      assert.ok(setCookie.includes('Path=/'));
    });

    test('session cookie includes Max-Age=2592000 (30 days validity)', async () => {
      const unlockRes = await fetch(`${localServer.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: 'LocalSafePass123' }),
      });
      assert.equal(unlockRes.status, 200);
      const setCookie = unlockRes.headers.get('set-cookie');
      assert.ok(setCookie.includes('Max-Age=2592000'));
    });
  });

});
