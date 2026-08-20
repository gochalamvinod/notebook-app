const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { spawnTestServer, extractCookie, getFreePort, createSandbox } = require('./test_helper.js');

// Crypto helpers matching server implementation
const SESSION_SECRET = crypto.createHash('sha256').update(process.env.SESSION_SECRET || 'leatherbound-master-session-salt-v3').digest();

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

function encryptSessionToken(key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_SECRET, iv);
  const encrypted = Buffer.concat([cipher.update(key), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + '.' + authTag.toString('hex') + '.' + encrypted.toString('hex');
}

function decryptSessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = Buffer.from(parts[2], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', SESSION_SECRET, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (e) {
    return null;
  }
}

describe('Tier 5: Adversarial Stress & Chaos Verification', () => {

  // =========================================================================
  // STRESS AREA 1: High-Concurrency Rapid CRUD Operations Across Multiple Books
  // =========================================================================
  describe('Area 1: High-Concurrency Rapid CRUD Operations', () => {
    let server;
    let cookie;
    const password = 'StressTestMasterPassword_2026!';

    before(async () => {
      server = await spawnTestServer();
      const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(setupRes.status, 200);
      cookie = extractCookie(setupRes);
      assert.ok(cookie, 'Setup must return valid session cookie');
    });

    after(async () => {
      if (server) await server.stop();
    });

    test('1.1: Concurrent creation of 20 notebooks simultaneously', async () => {
      const themes = ['brown', 'green', 'navy', 'burgundy', 'black'];
      const createPromises = [];

      for (let i = 0; i < 20; i++) {
        const title = `Concurrent Book #${i} - ${crypto.randomBytes(4).toString('hex')}`;
        const coverColor = themes[i % themes.length];
        createPromises.push(
          fetch(`${server.baseUrl}/api/books/create`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Cookie': `notebook_session=${cookie}`,
            },
            body: JSON.stringify({ title, coverColor }),
          }).then(async (r) => ({
            status: r.status,
            json: await r.json(),
            title,
          }))
        );
      }

      const results = await Promise.all(createPromises);
      for (const res of results) {
        assert.equal(res.status, 200, `Book creation should succeed: ${JSON.stringify(res.json)}`);
        assert.ok(res.json.ok);
        assert.ok(res.json.notebook.id);
        assert.equal(res.json.notebook.title, res.title);
      }

      // Verify books list consistency
      const listRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(listRes.status, 200);
      const listJson = await listRes.json();
      assert.ok(listJson.books.length >= 21, 'Should contain original book + 20 created books');
    });

    test('1.2: Interleaved race conditions: 30 rapid concurrent mixed CRUD operations', async () => {
      const listRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      const { books } = await listRes.json();
      assert.ok(books.length >= 5);

      const operations = [];

      // 6 concurrent renames
      for (let i = 0; i < 6; i++) {
        const targetBook = books[i % books.length];
        operations.push(
          fetch(`${server.baseUrl}/api/books/rename`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
            body: JSON.stringify({ bookId: targetBook.id, title: `Renamed-${i}-${Date.now()}` }),
          }).then(async (r) => ({ op: 'rename', status: r.status, json: await r.json() }))
        );
      }

      // 6 concurrent book switches
      for (let i = 0; i < 6; i++) {
        const targetBook = books[(i + 1) % books.length];
        operations.push(
          fetch(`${server.baseUrl}/api/books/switch`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
            body: JSON.stringify({ bookId: targetBook.id }),
          }).then(async (r) => ({ op: 'switch', status: r.status, json: await r.json() }))
        );
      }

      // 6 concurrent page content updates
      for (let i = 0; i < 6; i++) {
        const targetBook = books[(i + 2) % books.length];
        const updatedBook = {
          ...targetBook,
          pages: [
            { id: `p-race-${i}`, font: 'Arial', fontSize: '18px', html: `<p>Concurrent content update ${i}</p>` },
          ],
        };
        operations.push(
          fetch(`${server.baseUrl}/api/notebook`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
            body: JSON.stringify({ notebook: updatedBook }),
          }).then(async (r) => ({ op: 'savePage', status: r.status, json: await r.json() }))
        );
      }

      // 6 concurrent creates
      for (let i = 0; i < 6; i++) {
        operations.push(
          fetch(`${server.baseUrl}/api/books/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
            body: JSON.stringify({ title: `Race Created ${i}`, coverColor: 'navy' }),
          }).then(async (r) => ({ op: 'create', status: r.status, json: await r.json() }))
        );
      }

      // 6 concurrent reads
      for (let i = 0; i < 6; i++) {
        operations.push(
          fetch(`${server.baseUrl}/api/notebook`, {
            headers: { 'Cookie': `notebook_session=${cookie}` },
          }).then(async (r) => ({ op: 'read', status: r.status, json: await r.json() }))
        );
      }

      const results = await Promise.all(operations);
      for (const res of results) {
        assert.equal(res.status, 200, `Operation ${res.op} should return 200: ${JSON.stringify(res.json)}`);
        assert.ok(res.json.ok);
      }

      // Verify vault is still completely decryptable and valid
      const verifyRes = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(verifyRes.status, 200);
      const verifyJson = await verifyRes.json();
      assert.ok(verifyJson.vault.books.length > 0);
      assert.ok(verifyJson.vault.activeBookId);
    });

    test('1.3: Concurrent book deletion and strict minimum 1 book invariant', async () => {
      const listRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      const { books } = await listRes.json();
      
      const deletePromises = books.map((b) =>
        fetch(`${server.baseUrl}/api/books/delete`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
          body: JSON.stringify({ bookId: b.id }),
        }).then(async (r) => ({ status: r.status, json: await r.json(), bookId: b.id }))
      );

      const results = await Promise.all(deletePromises);

      const finalListRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(finalListRes.status, 200);
      const finalList = await finalListRes.json();

      // INVARIANT: There MUST be at least 1 book remaining at all times
      assert.ok(finalList.books.length >= 1, 'Minimum 1 notebook invariant must never be violated');
      assert.ok(finalList.activeBookId, 'activeBookId must remain valid');
      assert.ok(finalList.books.some((b) => b.id === finalList.activeBookId), 'activeBookId must match a real book');

      const rejectedDeletes = results.filter((r) => r.status === 400);
      assert.ok(rejectedDeletes.length >= 1, 'At least one delete must be rejected to maintain min 1 book');
    });

    test('1.4: Rapid sequential switching and page saving without state drift', async () => {
      const b1 = await fetch(`${server.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ title: 'SwitchTest Alpha', coverColor: 'green' }),
      }).then((r) => r.json());

      const b2 = await fetch(`${server.baseUrl}/api/books/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ title: 'SwitchTest Beta', coverColor: 'burgundy' }),
      }).then((r) => r.json());

      for (let i = 0; i < 10; i++) {
        const targetId = i % 2 === 0 ? b1.notebook.id : b2.notebook.id;
        const switchRes = await fetch(`${server.baseUrl}/api/books/switch`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
          body: JSON.stringify({ bookId: targetId }),
        });
        assert.equal(switchRes.status, 200);
        const switchJson = await switchRes.json();
        assert.equal(switchJson.activeBookId, targetId);

        const updateRes = await fetch(`${server.baseUrl}/api/notebook`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
          body: JSON.stringify({
            notebook: {
              id: targetId,
              title: i % 2 === 0 ? 'SwitchTest Alpha' : 'SwitchTest Beta',
              pages: [{ id: `p-sw-${i}`, font: 'Consolas', fontSize: '16px', html: `<p>Iteration ${i}</p>` }],
            },
          }),
        });
        assert.equal(updateRes.status, 200);
      }
    });
  });

  // =========================================================================
  // STRESS AREA 2: Large Payload Encryption / Decryption Stress (1MB+ to 10MB)
  // =========================================================================
  describe('Area 2: Large Payload Encryption/Decryption Stress', () => {
    let server;
    let cookie;
    const password = 'LargePayloadStressTestPass_1234!';

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

    test('2.1: 1.5MB single page rich-text payload roundtrip through Express API', async () => {
      const chunk = '<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. 🌟 <strong>Bold</strong> <em>Italic</em>. 日本語テキスト and symbols &amp; &lt;&gt;.</p>\n';
      const repeatCount = Math.ceil((1.5 * 1024 * 1024) / chunk.length);
      const largeHtml = chunk.repeat(repeatCount);
      assert.ok(Buffer.byteLength(largeHtml, 'utf8') >= 1.5 * 1024 * 1024, 'Payload should exceed 1.5MB');

      const nbRes = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      const { notebook } = await nbRes.json();

      notebook.pages = [
        {
          id: 'large-p-1',
          font: 'Georgia, serif',
          fontSize: '18px',
          html: largeHtml,
        },
      ];

      const saveRes = await fetch(`${server.baseUrl}/api/notebook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ notebook }),
      });
      assert.equal(saveRes.status, 200, 'Saving 1.5MB payload should succeed');

      // Read it back and verify byte-for-byte fidelity
      const fetchRes = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(fetchRes.status, 200);
      const fetchedJson = await fetchRes.json();

      assert.equal(fetchedJson.notebook.pages[0].html.length, largeHtml.length);
      assert.equal(fetchedJson.notebook.pages[0].html, largeHtml, 'Decrypted HTML must match byte-for-byte');
    });

    test('2.2: 50-page notebook with multi-page complex structures (~3MB total)', async () => {
      const pages = [];
      for (let i = 0; i < 50; i++) {
        const paragraph = `<p>Page ${i} content with random data: ${crypto.randomBytes(500).toString('hex')}</p>`;
        pages.push({
          id: `page-stress-${i}`,
          font: i % 2 === 0 ? 'Georgia, serif' : 'Arial, sans-serif',
          fontSize: `${14 + (i % 8)}px`,
          html: paragraph.repeat(40),
        });
      }

      const nbRes = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      const { notebook } = await nbRes.json();
      notebook.pages = pages;

      const saveRes = await fetch(`${server.baseUrl}/api/notebook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ notebook }),
      });
      assert.equal(saveRes.status, 200);

      // Verify all 50 pages retrieved accurately
      const readRes = await fetch(`${server.baseUrl}/api/notebook`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(readRes.status, 200);
      const readJson = await readRes.json();
      assert.equal(readJson.notebook.pages.length, 50);
      for (let i = 0; i < 50; i++) {
        assert.equal(readJson.notebook.pages[i].id, `page-stress-${i}`);
        assert.equal(readJson.notebook.pages[i].html, pages[i].html);
      }
    });

    test('2.3: Unit-level 10MB AES-256-GCM encryption & decryption stress benchmark', () => {
      const key = crypto.randomBytes(32);
      const largeObj = {
        meta: { name: '10MB Heavy Vault Stress' },
        records: Array.from({ length: 50000 }, (_, idx) => ({
          id: idx,
          hash: crypto.randomBytes(32).toString('hex'),
          text: `Sample multiline unicode text 🚀 🔒 📁 - Index ${idx} - ${'X'.repeat(100)}`,
          timestamp: new Date().toISOString(),
        })),
      };

      const startEnc = Date.now();
      const encrypted = encryptData(largeObj, key);
      const encTime = Date.now() - startEnc;

      assert.ok(encrypted.iv);
      assert.ok(encrypted.authTag);
      assert.ok(encrypted.data.length > 8 * 1024 * 1024, 'Ciphertext should exceed 8MB base64');

      const startDec = Date.now();
      const decrypted = decryptData(encrypted, key);
      const decTime = Date.now() - startDec;

      assert.equal(decrypted.records.length, 50000);
      assert.deepEqual(decrypted.records[1000], largeObj.records[1000]);
      assert.deepEqual(decrypted.records[49999], largeObj.records[49999]);
    });

    test('2.4: 2MB image binary upload and session retrieval', async () => {
      const imageBytes = crypto.randomBytes(2 * 1024 * 1024);
      const imageBase64 = `data:image/png;base64,${imageBytes.toString('base64')}`;

      const uploadRes = await fetch(`${server.baseUrl}/api/images`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
        body: JSON.stringify({ data: imageBase64, ext: 'png' }),
      });
      assert.equal(uploadRes.status, 200);
      const uploadJson = await uploadRes.json();
      assert.ok(uploadJson.url.startsWith('/images/'));

      // Fetch uploaded 2MB image
      const fetchRes = await fetch(`${server.baseUrl}${uploadJson.url}`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(fetchRes.status, 200);
      const fetchedBuffer = Buffer.from(await fetchRes.arrayBuffer());
      assert.deepEqual(fetchedBuffer, imageBytes, '2MB image binary must match exactly');
    });
  });

  // =========================================================================
  // STRESS AREA 3: Corrupted Ciphertext, Truncated Tokens & Wrong Password Hammering
  // =========================================================================
  describe('Area 3: Corrupted Ciphertext, Truncated Tokens & Password Hammering', () => {
    let server;
    let cookie;
    const password = 'TamperProofMasterPassword2026!';

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

    test('3.1: Brute-force invalid password hammer (50 rapid invalid unlock attempts)', async () => {
      const badPasswords = [
        'wrong',
        'admin',
        '1234',
        'password',
        'TamperProofMasterPassword2025!', // off by one char
        '',
        '   ',
        '🔥💣💥🚀',
        'A'.repeat(5000), // 5KB password
        'B'.repeat(50000), // 50KB password
        `' OR '1'='1`, // SQL injection probe
        `<script>alert(1)</script>`, // XSS probe
        '{"password": "test"}',
        'null',
        'undefined',
        ...Array.from({ length: 35 }, (_, i) => `RandomInvalidPass_${i}_${crypto.randomBytes(8).toString('hex')}`),
      ];

      const unlockPromises = badPasswords.map((badPass) =>
        fetch(`${server.baseUrl}/api/unlock`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: badPass }),
        }).then(async (r) => ({
          status: r.status,
          json: await r.json(),
        }))
      );

      const results = await Promise.all(unlockPromises);

      for (const res of results) {
        assert.equal(res.status, 401, 'Invalid password must return 401');
        assert.equal(res.json.error, 'Incorrect password.');
      }

      // Verify server is STILL ALIVE and healthy after the hammering
      const validUnlockRes = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(validUnlockRes.status, 200, 'Valid password unlock must immediately succeed');
    });

    test('3.2: Tampered, corrupted, and oversized session cookie tokens across all endpoints', async () => {
      const validKey = crypto.randomBytes(32);
      const validToken = encryptSessionToken(validKey);
      const parts = validToken.split('.');

      const maliciousTokens = [
        '', // empty
        'singleparttoken',
        'twoparts.token',
        'four.parts.token.here',
        'non-hex-iv.non-hex-tag.non-hex-data',
        `${parts[0]}.00000000000000000000000000000000.${parts[2]}`, // flipped authTag
        `000000000000000000000000.${parts[1]}.${parts[2]}`, // flipped IV
        `${parts[0]}.${parts[1]}.0000000000000000000000000000000000000000000000000000000000000000`, // flipped ciphertext
        parts[0].slice(0, 10) + '.' + parts[1] + '.' + parts[2], // truncated IV
        parts[0] + '.' + parts[1].slice(0, 10) + '.' + parts[2], // truncated authTag
        'a'.repeat(2000), // 2KB header
        'a'.repeat(16000), // 16KB oversized header
        'null',
        'undefined',
        '%00%00%00',
      ];

      for (const badToken of maliciousTokens) {
        // Test on /api/notebook
        const resNb = await fetch(`${server.baseUrl}/api/notebook`, {
          headers: { 'Cookie': `notebook_session=${encodeURIComponent(badToken)}` },
        });
        assert.ok([401, 431].includes(resNb.status), `Token should return 401 or 431 on /api/notebook: ${badToken.slice(0, 20)}`);

        // Test on /api/books
        const resBooks = await fetch(`${server.baseUrl}/api/books`, {
          headers: { 'Cookie': `notebook_session=${encodeURIComponent(badToken)}` },
        });
        assert.ok([401, 431].includes(resBooks.status), `Token should return 401 or 431 on /api/books: ${badToken.slice(0, 20)}`);

        // Test on /images/:filename
        const resImg = await fetch(`${server.baseUrl}/images/test.jpg`, {
          headers: { 'Cookie': `notebook_session=${encodeURIComponent(badToken)}` },
        });
        assert.ok([401, 431].includes(resImg.status), `Token should return 401 or 431 on /images/:filename: ${badToken.slice(0, 20)}`);
      }
    });

    test('3.3: Direct ciphertext bit-flip corruption on disk causes clean rejection', async () => {
      const dataFilePath = path.join(server.dataDir, 'notebook.enc.json');
      const fileContent = JSON.parse(fs.readFileSync(dataFilePath, 'utf8'));

      const rawDataBuf = Buffer.from(fileContent.data, 'base64');
      rawDataBuf[0] = rawDataBuf[0] ^ 0xff; // Invert first byte
      const corruptedFileContent = {
        ...fileContent,
        data: rawDataBuf.toString('base64'),
      };

      fs.writeFileSync(dataFilePath, JSON.stringify(corruptedFileContent), 'utf8');

      // Attempt unlock against corrupted disk file
      const unlockCorrupt = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(unlockCorrupt.status, 401, 'Corrupted ciphertext must be cleanly rejected');

      // Restore valid file for subsequent tests
      fs.writeFileSync(dataFilePath, JSON.stringify(fileContent), 'utf8');
      const unlockRestored = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(unlockRestored.status, 200);
    });

    test('3.4: Complete corruption of disk vault (invalid JSON, truncated files)', async () => {
      const dataFilePath = path.join(server.dataDir, 'notebook.enc.json');
      const original = fs.readFileSync(dataFilePath, 'utf8');

      // Test 1: empty file
      fs.writeFileSync(dataFilePath, '', 'utf8');
      const unlockEmpty = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(unlockEmpty.status, 401);

      // Test 2: garbage non-JSON
      fs.writeFileSync(dataFilePath, 'MALFORMED_GARBAGE_DATA_12345!@#$%', 'utf8');
      const unlockGarbage = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(unlockGarbage.status, 401);

      // Restore
      fs.writeFileSync(dataFilePath, original, 'utf8');
      const unlockOk = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(unlockOk.status, 200);
    });
  });

  // =========================================================================
  // STRESS AREA 4: Base64 Image Migration with Corrupt or Malformed Data URLs
  // =========================================================================
  describe('Area 4: Base64 Image Migration Stress Test with Malformed Data URLs', () => {
    let server;
    const password = 'ImageMigrationPass_2026!';

    test('4.1: Vault with malformed, corrupt, and valid base64 images unpacks gracefully', async () => {
      const salt = crypto.randomBytes(16).toString('hex');
      const key = deriveKey(password, salt);

      const validPngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      const validJpegBase64 = '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=';

      // Construct a multi-book vault with mixed corrupt, malformed, and valid images
      const initialVault = {
        version: 2,
        activeBookId: 'book-migr-1',
        books: [
          {
            id: 'book-migr-1',
            title: 'Image Chaos Book 1',
            coverColor: 'emerald',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            pages: [
              {
                id: 'p-migr-1',
                font: 'Georgia, serif',
                fontSize: '18px',
                html: `
                  <p>Valid Image:</p>
                  <img class="photo-thumb" src="data:image/png;base64,${validPngBase64}" alt="Valid PNG" style="width: 200px;">
                  <p>Corrupt non-base64 characters in data URL:</p>
                  <img src="data:image/png;base64,!!!NOT_BASE_64_CHARACTERS$$$@@@" alt="Corrupt 1">
                  <p>Empty base64 data URL:</p>
                  <img src="data:image/jpeg;base64," alt="Empty base64">
                `,
              },
              {
                id: 'p-migr-2',
                font: 'Georgia, serif',
                fontSize: '18px',
                html: `
                  <p>Valid JPEG Image:</p>
                  <img src="data:image/jpeg;base64,${validJpegBase64}" alt="Valid JPEG">
                  <p>Corrupt long payload:</p>
                  <img src="data:image/webp;base64,${'A'.repeat(50000)}---corrupt---" alt="Corrupt WebP">
                  <p>Standard external link (should remain untouched):</p>
                  <img src="https://example.com/external.png" alt="External">
                `,
              },
            ],
          },
        ],
      };

      const encrypted = encryptData(initialVault, key);
      const diskPayload = { version: 2, salt, ...encrypted };

      server = await spawnTestServer({ initialVault: diskPayload });

      // Unlock should trigger migrateBase64Images
      const unlockRes = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });

      assert.equal(unlockRes.status, 200, 'Unlock with malformed image tags should not crash');
      const unlockJson = await unlockRes.json();
      assert.ok(unlockJson.ok);
      const cookie = extractCookie(unlockRes);

      // Verify that valid PNG was migrated to a /images/ file
      const book = unlockJson.vault.books[0];
      const page1Html = book.pages[0].html;
      assert.ok(page1Html.includes('src="/images/'), 'Valid image must be migrated to /images/ path');
      assert.ok(page1Html.includes('class="photo-thumb"'), 'Image classes must be preserved');
      assert.ok(page1Html.includes('style="width: 200px;"'), 'Image styles must be preserved');

      // Verify external URL was NOT touched
      const page2Html = book.pages[1].html;
      assert.ok(page2Html.includes('src="https://example.com/external.png"'), 'External URL must remain intact');

      // Extract filename of migrated valid PNG
      const match = page1Html.match(/src="(\/images\/[^"]+)"/);
      assert.ok(match, 'Must match migrated image URL');
      const imgUrl = match[1];

      // Fetch the migrated image via session-gated endpoint
      const imgRes = await fetch(`${server.baseUrl}${imgUrl}`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(imgRes.status, 200, 'Migrated image must be fetchable');
      const imgBuffer = Buffer.from(await imgRes.arrayBuffer());
      assert.deepEqual(imgBuffer, Buffer.from(validPngBase64, 'base64'), 'Migrated image bytes must match original');

      await server.stop();
    });
  });

  // =========================================================================
  // STRESS AREA 5: Multi-Instance Serverless Simulation (10 Concurrent Requests)
  // =========================================================================
  describe('Area 5: Multi-Instance Serverless Simulation (10 Concurrent Requests)', () => {
    let server;
    let cookie;
    const password = 'ServerlessMultiInstancePass_2026!';
    const vercelDataDir = path.join('/tmp', 'data');

    before(async () => {
      try {
        if (fs.existsSync(vercelDataDir)) {
          fs.rmSync(vercelDataDir, { recursive: true, force: true });
        }
      } catch (e) {}

      server = await spawnTestServer({ isVercel: true });
      const setupRes = await fetch(`${server.baseUrl}/api/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(setupRes.status, 200);
      cookie = extractCookie(setupRes);
      assert.ok(cookie);
    });

    after(async () => {
      if (server) await server.stop();
      try {
        if (fs.existsSync(vercelDataDir)) {
          fs.rmSync(vercelDataDir, { recursive: true, force: true });
        }
      } catch (e) {}
    });

    test('5.1: 10 concurrent requests from simulated serverless instances with session cookie', async () => {
      const dummyPngBase64 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

      // 10 concurrent heterogeneous requests
      const concurrentTasks = [
        // Instance 1: Status check
        fetch(`${server.baseUrl}/api/status`, {
          headers: { 'Cookie': `notebook_session=${cookie}` },
        }).then(async (r) => ({ id: 1, type: 'status', status: r.status, data: await r.json() })),

        // Instance 2: Fetch books
        fetch(`${server.baseUrl}/api/books`, {
          headers: { 'Cookie': `notebook_session=${cookie}` },
        }).then(async (r) => ({ id: 2, type: 'getBooks', status: r.status, data: await r.json() })),

        // Instance 3: Fetch active notebook
        fetch(`${server.baseUrl}/api/notebook`, {
          headers: { 'Cookie': `notebook_session=${cookie}` },
        }).then(async (r) => ({ id: 3, type: 'getNotebook', status: r.status, data: await r.json() })),

        // Instance 4: Create new book A
        fetch(`${server.baseUrl}/api/books/create`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
          body: JSON.stringify({ title: 'Serverless Book Alpha', coverColor: 'emerald' }),
        }).then(async (r) => ({ id: 4, type: 'createBookA', status: r.status, data: await r.json() })),

        // Instance 5: Create new book B
        fetch(`${server.baseUrl}/api/books/create`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
          body: JSON.stringify({ title: 'Serverless Book Beta', coverColor: 'burgundy' }),
        }).then(async (r) => ({ id: 5, type: 'createBookB', status: r.status, data: await r.json() })),

        // Instance 6: Upload image
        fetch(`${server.baseUrl}/api/images`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
          body: JSON.stringify({ data: dummyPngBase64, ext: 'png' }),
        }).then(async (r) => ({ id: 6, type: 'uploadImage', status: r.status, data: await r.json() })),

        // Instance 7: Fetch books list again
        fetch(`${server.baseUrl}/api/books`, {
          headers: { 'Cookie': `notebook_session=${cookie}` },
        }).then(async (r) => ({ id: 7, type: 'getBooks2', status: r.status, data: await r.json() })),

        // Instance 8: Update page content
        fetch(`${server.baseUrl}/api/notebook`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${cookie}` },
          body: JSON.stringify({
            notebook: {
              id: 'book-default',
              title: 'Updated in Serverless',
              coverColor: 'brown',
              pages: [{ id: 'p-srv-1', font: 'Georgia', fontSize: '18px', html: '<p>Serverless content</p>' }],
            },
          }),
        }).then(async (r) => ({ id: 8, type: 'saveNotebook', status: r.status, data: await r.json() })),

        // Instance 9: Link preview request (unauthenticated proxy route)
        fetch(`${server.baseUrl}/api/proxy?url=http://example.com`, {
          headers: { 'Cookie': `notebook_session=${cookie}` },
        }).then((r) => ({ id: 9, type: 'proxy', status: r.status })),

        // Instance 10: Status check
        fetch(`${server.baseUrl}/api/status`, {
          headers: { 'Cookie': `notebook_session=${cookie}` },
        }).then(async (r) => ({ id: 10, type: 'status2', status: r.status, data: await r.json() })),
      ];

      const results = await Promise.all(concurrentTasks);

      for (const res of results) {
        assert.ok(
          res.status === 200 || res.status === 302 || res.status === 200,
          `Request ${res.id} (${res.type}) should succeed, got ${res.status}`
        );
      }

      // Verify final vault consistency
      const finalRes = await fetch(`${server.baseUrl}/api/books`, {
        headers: { 'Cookie': `notebook_session=${cookie}` },
      });
      assert.equal(finalRes.status, 200);
      const finalBooks = await finalRes.json();
      assert.ok(finalBooks.books.length >= 2, 'Books created in concurrent serverless instances should persist');
    });

    test('5.2: Serverless cookie SameSite=None and Secure flags verification', async () => {
      const res = await fetch(`${server.baseUrl}/api/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      assert.equal(res.status, 200);
      const setCookie = res.headers.get('set-cookie');
      assert.ok(setCookie, 'Set-Cookie header must be present');
      assert.ok(setCookie.includes('SameSite=None'), 'Serverless cookies must include SameSite=None');
      assert.ok(setCookie.includes('Secure'), 'Serverless cookies must include Secure');
      assert.ok(setCookie.includes('HttpOnly'), 'Serverless cookies must include HttpOnly');
      assert.ok(setCookie.includes('Max-Age=2592000'), 'Serverless cookies must include 30-day Max-Age');
    });

    test('5.3: Cross-process stateless multi-instance simulation (Serverless Instance A and B)', async () => {
      // Create shared directory for two separate serverless worker processes
      const { tmpDir, dataDir, imagesDir, appRoot } = createSandbox();
      const portA = await getFreePort();
      const portB = await getFreePort();
      const sharedSecret = 'serverless-stress-secret-key-32b!';

      const nodeModulesPath = path.join(appRoot, 'node_modules');
      const envA = {
        ...process.env,
        PORT: String(portA),
        NODE_PATH: nodeModulesPath,
        SESSION_SECRET: sharedSecret,
      };
      const envB = {
        ...process.env,
        PORT: String(portB),
        NODE_PATH: nodeModulesPath,
        SESSION_SECRET: sharedSecret,
      };

      const procA = spawn(process.execPath, ['server.js'], { cwd: tmpDir, env: envA, stdio: ['ignore', 'pipe', 'pipe'] });
      const procB = spawn(process.execPath, ['server.js'], { cwd: tmpDir, env: envB, stdio: ['ignore', 'pipe', 'pipe'] });

      const urlA = `http://127.0.0.1:${portA}`;
      const urlB = `http://127.0.0.1:${portB}`;

      // Wait for both to be ready
      for (let i = 0; i < 40; i++) {
        try {
          const [rA, rB] = await Promise.all([fetch(`${urlA}/api/status`), fetch(`${urlB}/api/status`)]);
          if (rA.ok && rB.ok) break;
        } catch (e) {
          await new Promise((r) => setTimeout(r, 100));
        }
      }

      try {
        // Setup on Instance A
        const setupRes = await fetch(`${urlA}/api/setup`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: 'CrossProcessServerlessPass!' }),
        });
        assert.equal(setupRes.status, 200);
        const crossCookie = extractCookie(setupRes);
        assert.ok(crossCookie);

        // Instance B has empty memory (sessionKey = null). Make 10 concurrent requests to Instance B!
        const bTasks = Array.from({ length: 10 }, (_, idx) =>
          fetch(`${urlB}/api/notebook`, {
            headers: { 'Cookie': `notebook_session=${crossCookie}` },
          }).then((r) => r.status)
        );

        const bStatuses = await Promise.all(bTasks);
        for (const st of bStatuses) {
          assert.equal(st, 200, 'Instance B must authenticate stateless cookie without local memory');
        }

        // Write from Instance B, read from Instance A
        const createOnB = await fetch(`${urlB}/api/books/create`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Cookie': `notebook_session=${crossCookie}` },
          body: JSON.stringify({ title: 'Created via Cold Instance B', coverColor: 'black' }),
        });
        assert.equal(createOnB.status, 200);

        const readOnA = await fetch(`${urlA}/api/books`, {
          headers: { 'Cookie': `notebook_session=${crossCookie}` },
        });
        assert.equal(readOnA.status, 200);
        const booksOnA = await readOnA.json();
        assert.ok(booksOnA.books.some((b) => b.title === 'Created via Cold Instance B'));
      } finally {
        procA.kill();
        procB.kill();
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
      }
    });
  });
});
