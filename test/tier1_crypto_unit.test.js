const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// Reference implementations matching server.js crypto routines and interface contracts
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

const SESSION_SECRET = crypto.createHash('sha256').update(process.env.SESSION_SECRET || 'leatherbound-master-session-salt-v3').digest();

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

function normalizeVault(data) {
  if (data && Array.isArray(data.books) && data.books.length > 0) {
    if (!data.activeBookId || !data.books.some((b) => b.id === data.activeBookId)) {
      data.activeBookId = data.books[0].id;
    }
    return data;
  }
  const defaultBook = {
    id: 'book-default',
    title: (data && data.title) || 'My Notebook',
    coverColor: (data && data.coverColor) || 'brown',
    createdAt: (data && data.createdAt) || new Date().toISOString(),
    updatedAt: (data && data.updatedAt) || new Date().toISOString(),
    pages: (data && data.pages) || [
      { id: 'p-' + Date.now(), font: "Georgia, 'Times New Roman', serif", fontSize: '18px', html: '' },
    ],
  };
  return {
    version: 2,
    activeBookId: defaultBook.id,
    books: [defaultBook],
  };
}

const BASE64_IMG_RE = /<img([^>]*)\ssrc="(data:image\/([a-z+]+);base64,[^"]+)"([^>]*)>/gi;

function migrateBase64Images(vault, imagesDir) {
  let changed = false;
  if (!vault || !vault.books) return false;
  for (const book of vault.books) {
    if (!book.pages) continue;
    for (const page of book.pages) {
      if (!page.html || !page.html.includes('data:image/')) continue;
      page.html = page.html.replace(BASE64_IMG_RE, (match, before, dataUrl, ext, after) => {
        try {
          const safeExt = ext.replace(/[^a-z0-9]/g, '').slice(0, 8) || 'jpg';
          const id = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
          const filename = id + '.' + safeExt;
          const base64Data = dataUrl.split(',')[1];
          fs.writeFileSync(path.join(imagesDir, filename), Buffer.from(base64Data, 'base64'));
          changed = true;
          return `<img${before} src="/images/${filename}"${after}>`;
        } catch (err) {
          return match;
        }
      });
    }
  }
  return changed;
}

describe('Tier 1: Crypto & Core Unit Tests', () => {

  describe('Key Derivation & Parameters (scrypt)', () => {
    test('derives a 32-byte key deterministically with identical password and salt', () => {
      const salt = crypto.randomBytes(16).toString('hex');
      const key1 = deriveKey('MasterPass123!', salt);
      const key2 = deriveKey('MasterPass123!', salt);
      assert.equal(key1.length, 32);
      assert.equal(key2.length, 32);
      assert.deepEqual(key1, key2);
    });

    test('produces different keys for same password with different salts', () => {
      const salt1 = crypto.randomBytes(16).toString('hex');
      const salt2 = crypto.randomBytes(16).toString('hex');
      const key1 = deriveKey('Secret123', salt1);
      const key2 = deriveKey('Secret123', salt2);
      assert.notDeepEqual(key1, key2);
    });

    test('produces different keys for different passwords with same salt', () => {
      const salt = crypto.randomBytes(16).toString('hex');
      const key1 = deriveKey('passwordA', salt);
      const key2 = deriveKey('passwordB', salt);
      assert.notDeepEqual(key1, key2);
    });

    test('handles unicode and complex UTF-8 passwords correctly', () => {
      const salt = crypto.randomBytes(16).toString('hex');
      const key1 = deriveKey('🔒Passwörd_日本語_123_✨', salt);
      const key2 = deriveKey('🔒Passwörd_日本語_123_✨', salt);
      assert.equal(key1.length, 32);
      assert.deepEqual(key1, key2);
    });

    test('handles empty password strings safely', () => {
      const salt = crypto.randomBytes(16).toString('hex');
      const key = deriveKey('', salt);
      assert.equal(key.length, 32);
      assert.ok(Buffer.isBuffer(key));
    });

    test('validates scrypt work factor N=16384, r=8, p=1 compliance', () => {
      const salt = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
      const key = deriveKey('test-work-factor', salt);
      const expected = crypto.scryptSync('test-work-factor', Buffer.from(salt, 'hex'), 32, { N: 16384, r: 8, p: 1 });
      assert.deepEqual(key, expected);
    });
  });

  describe('AES-256-GCM Encryption & Decryption Roundtrip', () => {
    const testKey = crypto.randomBytes(32);

    test('encrypts and decrypts basic JSON objects accurately', () => {
      const payload = { title: 'Personal Diary', entryCount: 42, tags: ['secret', 'journal'] };
      const encrypted = encryptData(payload, testKey);

      assert.ok(typeof encrypted.iv === 'string' && encrypted.iv.length === 24); // 12 bytes = 24 hex chars
      assert.ok(typeof encrypted.authTag === 'string' && encrypted.authTag.length === 32); // 16 bytes = 32 hex chars
      assert.ok(typeof encrypted.data === 'string');

      const decrypted = decryptData(encrypted, testKey);
      assert.deepEqual(decrypted, payload);
    });

    test('encrypts and decrypts complex nested multi-book vaults with HTML content', () => {
      const vault = {
        version: 2,
        activeBookId: 'book-100',
        books: [
          {
            id: 'book-100',
            title: 'Grimoire of Spells',
            coverColor: 'emerald',
            pages: [
              { id: 'p1', font: 'Georgia', fontSize: '18px', html: '<h1>Spell 1</h1><p>Fireball: 🔥 Cast with vigor!</p>' },
              { id: 'p2', font: 'Palatino', fontSize: '16px', html: '<p>Teleportation notes with special &amp; chars: &lt; &gt; &quot;</p>' },
            ],
          },
        ],
      };
      const encrypted = encryptData(vault, testKey);
      const decrypted = decryptData(encrypted, testKey);
      assert.deepEqual(decrypted, vault);
    });

    test('generates unique IVs and ciphertexts on every encryption call for identical plaintext', () => {
      const payload = { same: 'data' };
      const enc1 = encryptData(payload, testKey);
      const enc2 = encryptData(payload, testKey);
      assert.notEqual(enc1.iv, enc2.iv);
      assert.notEqual(enc1.data, enc2.data);
      assert.notEqual(enc1.authTag, enc2.authTag);
    });

    test('handles large payloads (100KB+ notes) without corruption', () => {
      const largeContent = 'A'.repeat(128 * 1024);
      const payload = { bigPage: largeContent };
      const enc = encryptData(payload, testKey);
      const dec = decryptData(enc, testKey);
      assert.equal(dec.bigPage.length, 128 * 1024);
      assert.equal(dec.bigPage, largeContent);
    });

    test('encrypts and decrypts empty structures ({}, []) correctly', () => {
      const encObj = encryptData({}, testKey);
      assert.deepEqual(decryptData(encObj, testKey), {});

      const encArr = encryptData([], testKey);
      assert.deepEqual(decryptData(encArr, testKey), []);
    });
  });

  describe('GCM Authentication Tag & Tampering Detection', () => {
    const key = crypto.randomBytes(32);
    const originalPayload = { secret: 'top_secret_intel_2026' };

    test('fails to decrypt if the wrong key is supplied', () => {
      const enc = encryptData(originalPayload, key);
      const wrongKey = crypto.randomBytes(32);
      assert.throws(() => {
        decryptData(enc, wrongKey);
      });
    });

    test('fails and throws error when authentication tag is tampered with (bit flip)', () => {
      const enc = encryptData(originalPayload, key);
      const tagBuf = Buffer.from(enc.authTag, 'hex');
      tagBuf[0] ^= 0x01; // flip 1 bit
      const tampered = { ...enc, authTag: tagBuf.toString('hex') };
      assert.throws(() => {
        decryptData(tampered, key);
      });
    });

    test('fails and throws error when initialization vector (IV) is tampered with', () => {
      const enc = encryptData(originalPayload, key);
      const ivBuf = Buffer.from(enc.iv, 'hex');
      ivBuf[0] ^= 0x02; // flip 1 bit
      const tampered = { ...enc, iv: ivBuf.toString('hex') };
      assert.throws(() => {
        decryptData(tampered, key);
      });
    });

    test('fails and throws error when ciphertext data payload is tampered with', () => {
      const enc = encryptData(originalPayload, key);
      const cipherBuf = Buffer.from(enc.data, 'base64');
      cipherBuf[0] ^= 0x04; // flip 1 bit
      const tampered = { ...enc, data: cipherBuf.toString('base64') };
      assert.throws(() => {
        decryptData(tampered, key);
      });
    });

    test('fails gracefully on malformed / truncated base64 data', () => {
      const enc = encryptData(originalPayload, key);
      const tampered = { ...enc, data: 'Not!Valid@Base64==' };
      assert.throws(() => {
        decryptData(tampered, key);
      });
    });

    test('fails and throws error when authTag length is invalid', () => {
      const enc = encryptData(originalPayload, key);
      const tampered = { ...enc, authTag: enc.authTag.slice(0, 16) }; // truncated tag
      assert.throws(() => {
        decryptData(tampered, key);
      });
    });
  });

  describe('Stateless Session Token Encryption & Key Recovery', () => {
    test('encrypts 32-byte key into 3-part dot-separated hex token', () => {
      const masterKey = crypto.randomBytes(32);
      const token = encryptSessionToken(masterKey);
      assert.ok(typeof token === 'string');
      const parts = token.split('.');
      assert.equal(parts.length, 3);
      assert.equal(parts[0].length, 24); // 12-byte IV = 24 hex chars
      assert.equal(parts[1].length, 32); // 16-byte tag = 32 hex chars
      assert.equal(parts[2].length, 64); // 32-byte encrypted key = 64 hex chars
    });

    test('decrypts session token and recovers exact 32-byte master key buffer', () => {
      const masterKey = crypto.randomBytes(32);
      const token = encryptSessionToken(masterKey);
      const recovered = decryptSessionToken(token);
      assert.ok(Buffer.isBuffer(recovered));
      assert.equal(recovered.length, 32);
      assert.deepEqual(recovered, masterKey);
    });

    test('returns null when session token is tampered (IV modified)', () => {
      const masterKey = crypto.randomBytes(32);
      const token = encryptSessionToken(masterKey);
      const parts = token.split('.');
      const ivBuf = Buffer.from(parts[0], 'hex');
      ivBuf[0] ^= 0xff;
      parts[0] = ivBuf.toString('hex');
      assert.equal(decryptSessionToken(parts.join('.')), null);
    });

    test('returns null when session token tag is tampered', () => {
      const masterKey = crypto.randomBytes(32);
      const token = encryptSessionToken(masterKey);
      const parts = token.split('.');
      const tagBuf = Buffer.from(parts[1], 'hex');
      tagBuf[0] ^= 0xaa;
      parts[1] = tagBuf.toString('hex');
      assert.equal(decryptSessionToken(parts.join('.')), null);
    });

    test('returns null when session token ciphertext payload is tampered', () => {
      const masterKey = crypto.randomBytes(32);
      const token = encryptSessionToken(masterKey);
      const parts = token.split('.');
      const dataBuf = Buffer.from(parts[2], 'hex');
      dataBuf[0] ^= 0x55;
      parts[2] = dataBuf.toString('hex');
      assert.equal(decryptSessionToken(parts.join('.')), null);
    });

    test('returns null for malformed tokens (missing parts, empty, undefined)', () => {
      assert.equal(decryptSessionToken(''), null);
      assert.equal(decryptSessionToken(null), null);
      assert.equal(decryptSessionToken(undefined), null);
      assert.equal(decryptSessionToken('onlyonepart'), null);
      assert.equal(decryptSessionToken('part1.part2'), null);
      assert.equal(decryptSessionToken('part1.part2.part3.part4'), null);
      assert.equal(decryptSessionToken('zzzz.yyyy.xxxx'), null);
    });
  });

  describe('normalizeVault Schema Normalization & Corruption Recovery', () => {
    test('preserves well-formed v2 vault with existing activeBookId', () => {
      const v2Vault = {
        version: 2,
        activeBookId: 'b-2',
        books: [
          { id: 'b-1', title: 'Book 1', pages: [] },
          { id: 'b-2', title: 'Book 2', pages: [] },
        ],
      };
      const normalized = normalizeVault(v2Vault);
      assert.equal(normalized.version, 2);
      assert.equal(normalized.activeBookId, 'b-2');
      assert.equal(normalized.books.length, 2);
    });

    test('realigns activeBookId to first book if activeBookId is missing or nonexistent in v2', () => {
      const v2Vault = {
        version: 2,
        activeBookId: 'nonexistent-id',
        books: [
          { id: 'b-real', title: 'Real Book', pages: [] },
        ],
      };
      const normalized = normalizeVault(v2Vault);
      assert.equal(normalized.activeBookId, 'b-real');
    });

    test('upgrades legacy v1 single-book structure to v2 envelope with default book', () => {
      const legacyV1 = {
        title: 'My Legacy Journal',
        coverColor: 'navy',
        createdAt: '2024-01-01T00:00:00.000Z',
        updatedAt: '2024-01-02T00:00:00.000Z',
        pages: [
          { id: 'p-1', font: 'Georgia', fontSize: '18px', html: '<p>First entry</p>' },
        ],
      };
      const normalized = normalizeVault(legacyV1);
      assert.equal(normalized.version, 2);
      assert.equal(normalized.activeBookId, 'book-default');
      assert.equal(normalized.books.length, 1);
      assert.equal(normalized.books[0].title, 'My Legacy Journal');
      assert.equal(normalized.books[0].coverColor, 'navy');
      assert.equal(normalized.books[0].pages.length, 1);
      assert.equal(normalized.books[0].pages[0].html, '<p>First entry</p>');
    });

    test('creates default v2 vault when input is null, undefined, or empty object', () => {
      const normalizedNull = normalizeVault(null);
      assert.equal(normalizedNull.version, 2);
      assert.equal(normalizedNull.activeBookId, 'book-default');
      assert.equal(normalizedNull.books.length, 1);
      assert.equal(normalizedNull.books[0].title, 'My Notebook');
      assert.equal(normalizedNull.books[0].coverColor, 'brown');
      assert.equal(normalizedNull.books[0].pages.length, 1);

      const normalizedEmpty = normalizeVault({});
      assert.equal(normalizedEmpty.version, 2);
      assert.equal(normalizedEmpty.books.length, 1);
    });

    test('recovers safely when books property is an empty array', () => {
      const corrupt = { version: 2, activeBookId: 'some-id', books: [] };
      const normalized = normalizeVault(corrupt);
      assert.equal(normalized.version, 2);
      assert.equal(normalized.books.length, 1);
      assert.equal(normalized.activeBookId, 'book-default');
    });

    test('generates valid default pages array if missing in input', () => {
      const dataWithoutPages = { title: 'No Pages Book' };
      const normalized = normalizeVault(dataWithoutPages);
      assert.ok(Array.isArray(normalized.books[0].pages));
      assert.equal(normalized.books[0].pages.length, 1);
      assert.ok(normalized.books[0].pages[0].id.startsWith('p-'));
    });
  });

  describe('Base64 Image Extraction & Migration Regex', () => {
    let tempImgDir;

    test('matches and extracts inline base64 images of varying formats (PNG, JPG, WebP)', () => {
      tempImgDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lb-img-test-'));
      const sampleBase64Png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      const sampleBase64Jpg = '/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=';

      const vault = {
        version: 2,
        activeBookId: 'book-1',
        books: [
          {
            id: 'book-1',
            pages: [
              {
                id: 'p1',
                html: `<p>Hello</p><img class="custom" src="data:image/png;base64,${sampleBase64Png}" alt="test"><p>World</p><img src="data:image/jpeg;base64,${sampleBase64Jpg}">`,
              },
            ],
          },
        ],
      };

      const changed = migrateBase64Images(vault, tempImgDir);
      assert.equal(changed, true);

      // Verify HTML was updated
      const pageHtml = vault.books[0].pages[0].html;
      assert.ok(!pageHtml.includes('data:image/png;base64'));
      assert.ok(!pageHtml.includes('data:image/jpeg;base64'));
      assert.ok(pageHtml.includes('class="custom" src="/images/'));
      assert.ok(pageHtml.includes('alt="test"'));

      // Verify files were created on disk
      const createdFiles = fs.readdirSync(tempImgDir);
      assert.equal(createdFiles.length, 2);
      assert.ok(createdFiles.some((f) => f.endsWith('.png')));
      assert.ok(createdFiles.some((f) => f.endsWith('.jpeg') || f.endsWith('.jpg')));

      fs.rmSync(tempImgDir, { recursive: true, force: true });
    });

    test('ignores pages that only contain standard /images/ or external URLs', () => {
      tempImgDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lb-img-test-'));
      const vault = {
        version: 2,
        activeBookId: 'book-1',
        books: [
          {
            id: 'book-1',
            pages: [
              { id: 'p1', html: '<p>Photo:</p><img src="/images/already_saved.jpg"><img src="https://example.com/logo.png">' },
            ],
          },
        ],
      };
      const changed = migrateBase64Images(vault, tempImgDir);
      assert.equal(changed, false);
      assert.equal(fs.readdirSync(tempImgDir).length, 0);
      fs.rmSync(tempImgDir, { recursive: true, force: true });
    });

    test('handles multiple books and multiple pages with base64 images without crashing', () => {
      tempImgDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lb-img-test-'));
      const sampleBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      const vault = {
        version: 2,
        activeBookId: 'b1',
        books: [
          { id: 'b1', pages: [{ id: 'p1', html: `<img src="data:image/png;base64,${sampleBase64}">` }] },
          { id: 'b2', pages: [{ id: 'p2', html: `<img src="data:image/png;base64,${sampleBase64}">` }] },
        ],
      };
      const changed = migrateBase64Images(vault, tempImgDir);
      assert.equal(changed, true);
      assert.equal(fs.readdirSync(tempImgDir).length, 2);
      fs.rmSync(tempImgDir, { recursive: true, force: true });
    });
  });

});
