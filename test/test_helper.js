const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');
const http = require('http');
const { spawn } = require('child_process');

async function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close((err) => {
        if (err) reject(err);
        else resolve(port);
      });
    });
  });
}

function createSandbox() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lb-sandbox-'));
  const appRoot = path.resolve(__dirname, '..');
  
  // Copy server.js
  fs.copyFileSync(path.join(appRoot, 'server.js'), path.join(tmpDir, 'server.js'));
  
  // Copy public directory recursively
  const publicSrc = path.join(appRoot, 'public');
  const publicDest = path.join(tmpDir, 'public');
  fs.cpSync(publicSrc, publicDest, { recursive: true });
  
  // Ensure data directory exists
  const dataDir = path.join(tmpDir, 'data');
  const imagesDir = path.join(dataDir, 'images');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(imagesDir, { recursive: true });

  return { tmpDir, dataDir, imagesDir, appRoot };
}

async function spawnTestServer(options = {}) {
  const { isVercel = false, envOverrides = {}, initialVault = null } = options;
  const { tmpDir, dataDir, imagesDir, appRoot } = createSandbox();
  const port = await getFreePort();

  if (initialVault) {
    fs.writeFileSync(
      path.join(dataDir, 'notebook.enc.json'),
      typeof initialVault === 'string' ? initialVault : JSON.stringify(initialVault),
      'utf8'
    );
  }

  const nodeModulesPath = path.join(appRoot, 'node_modules');
  const env = {
    ...process.env,
    PORT: String(port),
    NODE_PATH: nodeModulesPath,
    ...envOverrides,
  };
  if (isVercel) {
    env.VERCEL = '1';
  } else {
    delete env.VERCEL;
  }

  const spawnArgs = isVercel
    ? ['-e', `const app = require('./server.js'); app.listen(${port});`]
    : ['server.js'];

  const proc = spawn(process.execPath, spawnArgs, {
    cwd: tmpDir,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const baseUrl = `http://127.0.0.1:${port}`;

  // Poll until ready
  let ready = false;
  for (let i = 0; i < 50; i++) {
    try {
      const res = await fetch(`${baseUrl}/api/status`);
      if (res.ok) {
        ready = true;
        break;
      }
    } catch (e) {
      await new Promise((r) => setTimeout(r, 80));
    }
  }

  if (!ready) {
    proc.kill();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    throw new Error(`Server failed to start on port ${port}`);
  }

  return {
    port,
    baseUrl,
    proc,
    tmpDir,
    dataDir,
    imagesDir,
    async stop() {
      return new Promise((resolve) => {
        if (proc.killed || proc.exitCode !== null) {
          try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
          return resolve();
        }
        const timer = setTimeout(() => {
          try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
          resolve();
        }, 1500);
        proc.on('close', () => {
          clearTimeout(timer);
          try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) {}
          resolve();
        });
        try {
          proc.kill();
        } catch (e) {
          clearTimeout(timer);
          resolve();
        }
      });
    },
  };
}

function extractCookie(response) {
  const setCookie = response.headers.get('set-cookie');
  if (!setCookie) return null;
  const match = setCookie.match(/notebook_session=([^;]+)/);
  return match ? match[1] : null;
}

module.exports = {
  getFreePort,
  createSandbox,
  spawnTestServer,
  extractCookie,
};
