/**
 * Master E2E & Unit Test Suite Runner
 * 3D Leatherbound Notebook
 *
 * Runs all 4 test tiers:
 * - Tier 1: Crypto & Core Unit Tests (test/tier1_crypto_unit.test.js)
 * - Tier 2: API Integration Tests (test/tier2_api_integration.test.js)
 * - Tier 3: UI & Browser Logic Tests (test/tier3_ui_browser.test.js)
 * - Tier 4: Compatibility & Serverless Tests (test/tier4_compat_serverless.test.js)
 */

const { spawn } = require('child_process');
const path = require('path');

const TIERS = [
  {
    tier: 'Tier 1',
    name: 'Crypto & Core Unit Tests',
    file: 'test/tier1_crypto_unit.test.js',
    minTests: 20,
  },
  {
    tier: 'Tier 2',
    name: 'API Integration Tests',
    file: 'test/tier2_api_integration.test.js',
    minTests: 25,
  },
  {
    tier: 'Tier 3',
    name: 'UI & Browser Logic Tests',
    file: 'test/tier3_ui_browser.test.js',
    minTests: 15,
  },
  {
    tier: 'Tier 4',
    name: 'Compatibility & Serverless Tests',
    file: 'test/tier4_compat_serverless.test.js',
    minTests: 15,
  },
  {
    tier: 'Tier 5A',
    name: 'Adversarial Boundary Coverage',
    file: 'test/tier5_adversarial_boundary.test.js',
    minTests: 30,
  },
  {
    tier: 'Tier 5B',
    name: 'Adversarial Stress & Chaos',
    file: 'test/tier5_adversarial_stress.test.js',
    minTests: 15,
  },
  {
    tier: 'Tier 6',
    name: 'Mega Comprehensive Tests',
    file: 'test/tier6_mega_comprehensive.test.js',
    minTests: 1000,
  },
  {
    tier: 'Tier 7',
    name: 'Hyper-Scale 10,000+ Stress Suite',
    file: 'test/tier7_hyper_10k.test.js',
    minTests: 10000,
  },
  {
    tier: 'Tier 8',
    name: '100k (1 Lakh) Website Backtest Matrix',
    file: 'test/tier8_100k_website_backtest.test.js',
    minTests: 100,
  },
];

async function runTestFile(file) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const appDir = path.resolve(__dirname, '..');
    const proc = spawn(process.execPath, ['--test', file], {
      cwd: appDir,
      env: { ...process.env, FORCE_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => { stderr += d.toString(); });

    proc.on('close', (code) => {
      const durationMs = Date.now() - startTime;

      // Extract test metrics from stdout
      let totalTests = 0;
      let passed = 0;
      let failed = 0;

      const passMatch = stdout.match(/ℹ pass (\d+)/);
      if (passMatch) passed = parseInt(passMatch[1], 10);

      const failMatch = stdout.match(/ℹ fail (\d+)/);
      if (failMatch) failed = parseInt(failMatch[1], 10);

      const testsMatch = stdout.match(/ℹ tests (\d+)/);
      if (testsMatch) totalTests = parseInt(testsMatch[1], 10);
      else totalTests = passed + failed;

      resolve({
        code,
        passed,
        failed,
        totalTests,
        durationMs,
        stdout,
        stderr,
      });
    });
  });
}

async function main() {
  console.log('\n' + '='.repeat(78));
  console.log('  📖 3D LEATHERBOUND NOTEBOOK — AUTOMATED 4-TIER TEST SUITE RUNNER');
  console.log('='.repeat(78) + '\n');

  const results = [];
  let allPassed = true;
  const overallStart = Date.now();

  for (const t of TIERS) {
    process.stdout.write(`  ⏳ Running ${t.tier}: ${t.name}... `);
    const result = await runTestFile(t.file);
    results.push({ ...t, ...result });

    if (result.code === 0 && result.failed === 0) {
      console.log(`\x1b[32mPASS\x1b[0m (${result.passed}/${result.totalTests} tests in ${(result.durationMs / 1000).toFixed(2)}s)`);
    } else {
      console.log(`\x1b[31mFAIL\x1b[0m (${result.failed} failed out of ${result.totalTests})`);
      allPassed = false;
      if (result.stdout) console.log(result.stdout);
      if (result.stderr) console.error(result.stderr);
    }
  }

  const totalDuration = ((Date.now() - overallStart) / 1000).toFixed(2);
  const totalTestsCount = results.reduce((sum, r) => sum + r.totalTests, 0);
  const totalPassedCount = results.reduce((sum, r) => sum + r.passed, 0);
  const totalFailedCount = results.reduce((sum, r) => sum + r.failed, 0);

  console.log('\n' + '-'.repeat(78));
  console.log('  TEST SUITE EXECUTION SUMMARY');
  console.log('-'.repeat(78));
  console.log('  Tier     Description                     Threshold  Passed  Failed  Status');
  console.log('  ' + '-'.repeat(74));

  for (const r of results) {
    const statusStr = r.failed === 0 && r.code === 0 ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m';
    const tierPadded = r.tier.padEnd(8);
    const namePadded = r.name.padEnd(32);
    const minPadded = (`≥${r.minTests}`).padEnd(10);
    const passPadded = String(r.passed).padEnd(8);
    const failPadded = String(r.failed).padEnd(8);

    console.log(`  ${tierPadded} ${namePadded} ${minPadded} ${passPadded} ${failPadded} ${statusStr}`);
  }

  console.log('  ' + '-'.repeat(74));
  console.log(`  TOTAL:   ${totalPassedCount} Passed, ${totalFailedCount} Failed out of ${totalTestsCount} tests in ${totalDuration}s\n`);

  if (allPassed) {
    console.log('  \x1b[32m✨ ALL TEST TIERS PASSED PERFECTLY WITH ZERO DEFECTS ✨\x1b[0m\n');
    process.exit(0);
  } else {
    console.error('  \x1b[31m❌ TEST SUITE FAILED. Check individual tier logs above.\x1b[0m\n');
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('Test runner fatal error:', err);
    process.exit(1);
  });
}

module.exports = { runTestFile, TIERS };
