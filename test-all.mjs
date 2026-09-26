#!/usr/bin/env node
// test-all.mjs - one command that exercises the whole product end to end.
//
//   node test-all.mjs
//
// Builds a throwaway git repo in the OS temp dir, installs the hook, makes
// real commits, then attacks the chain five different ways and asserts each is
// caught. Cleans up after itself.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const CLI = join(HERE, 'witness.mjs');
const INSTALL = join(HERE, 'install-hook.mjs');

let pass = 0, fail = 0;
const check = (name, cond, detail = '') => {
  if (cond) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (detail ? '\n         ' + detail : '')); }
};
const section = (s) => console.log('\n' + s);
const sha = (s) => createHash('sha256').update(s).digest('hex');

const repo = mkdtempSync(join(tmpdir(), 'witness-test-'));
const keyDir = repo + '-keys';
const env = { ...process.env, WITNESS_KEY_DIR: keyDir };
const chainPath = join(repo, '.witness/chain.jsonl');

// spawnSync rather than execFileSync: git sends hook output to the child's
// stderr, and execFileSync hands back only stdout when the command succeeds --
// so a passing commit's output would silently look like silence.
const run = (cmd, args, extraEnv) => {
  const r = spawnSync(cmd, args, { cwd: repo, env: { ...env, ...extraEnv }, encoding: 'utf8' });
  return { code: r.status ?? 1, out: (r.stdout || '') + (r.stderr || '') };
};
const attempt = (r) => r;

const git = (args, extraEnv) => run('git', args, extraEnv);
const witness = (args) => run(process.execPath, [CLI, ...args]);

const readChain = () => (existsSync(chainPath)
  ? readFileSync(chainPath, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
  : []);

// Rewrites one entry's content, optionally re-deriving its hash to hide the edit.
// This mirrors witness.mjs's own body()/canon() so the forgery is a real one:
// with rehash=true the content-hash check passes, leaving only the signature.
const forge = (text, i, mutate, rehash = false) => {
  const lines = text.trim().split('\n');
  const e = JSON.parse(lines[i]);
  mutate(e);
  if (rehash) {
    const { hash, signature, ...rest } = e;
    e.hash = sha(JSON.stringify(Object.keys(rest).sort().reduce((a, k) => (a[k] = rest[k], a), {})));
  }
  lines[i] = JSON.stringify(e);
  return lines.join('\n') + '\n';
};

try {
  section('1. unit selftest');
  const st = attempt(witness(['selftest']));
  console.log('     ' + st.out.trim().split('\n').slice(-2).join(' | '));
  check('selftest passes', st.code === 0 && / 0 failed/.test(st.out));

  section('2. install into a fresh repo');
  git(['init', '-q']);
  git(['config', 'user.email', 'test@local']);
  git(['config', 'user.name', 'tester']);
  const inst = attempt(run(process.execPath, [INSTALL, repo]));
  check('installer succeeded', inst.code === 0, inst.out.trim());
  check('commit-msg hook installed', existsSync(join(repo, '.git/hooks/commit-msg')));
  const pinned = git(['config', 'witness.bin']);
  check('tool path pinned in git config', pinned.out.includes('witness.mjs'), pinned.out.trim());
  check('pinned path is absolute', /^[A-Za-z]:[\\/]/.test(pinned.out.trim()), pinned.out.trim());
  check('no private key inside the repo', !existsSync(join(repo, '.witness/keys.json')));

  section('3. real commits are recorded');
  writeFileSync(join(repo, 'app.js'), 'export const v = 1;\n');
  git(['add', 'app.js']);
  const c1 = attempt(git(['commit', '-q', '-m', 'first change']));
  check('commit 1 recorded', /witness: recorded #0/.test(c1.out), c1.out.trim());
  check('private key created outside the repo', existsSync(keyDir));
  check('public key written into the repo', existsSync(join(repo, '.witness/pubkey.json')));

  writeFileSync(join(repo, 'lib.js'), 'export const y = 2;\n');
  git(['add', 'lib.js']);
  const c2 = attempt(git(['commit', '-q', '-m', 'second change']));
  check('commit 2 recorded', /witness: recorded #1/.test(c2.out), c2.out.trim());

  section('4. summaries are real messages, not diffstats');
  const entries = readChain();
  check('entry 0 summary is the commit message', entries[0]?.summary === 'first change', JSON.stringify(entries[0]?.summary));
  check('entry 1 summary is the commit message', entries[1]?.summary === 'second change', JSON.stringify(entries[1]?.summary));
  check('both files recorded', JSON.stringify(entries[0]?.files) === '["app.js"]' && JSON.stringify(entries[1]?.files) === '["lib.js"]');

  section('5. the escape hatch is visible, not silent');
  writeFileSync(join(repo, 'skip.js'), 'export const z = 3;\n');
  git(['add', 'skip.js']);
  const skip = attempt(git(['commit', '-q', '-m', 'skipped'], { WITNESS_SKIP: '1' }));
  check('WITNESS_SKIP still commits', skip.code === 0, skip.out.trim());
  check('WITNESS_SKIP records nothing', readChain().length === 2);
  check('WITNESS_SKIP announces itself', /nothing recorded/.test(skip.out), skip.out.trim());

  const original = readFileSync(chainPath, 'utf8');

  section('6. ATTACK 1 - edit content, keep hash and signature');
  writeFileSync(chainPath, forge(original, 0, (e) => { e.summary = 'lies about what happened'; }));
  const a1 = attempt(witness(['verify']));
  check('detected', a1.code === 1 && /TAMPERING DETECTED/.test(a1.out), a1.out.trim());
  check('blamed on the content hash', /content hash mismatch/.test(a1.out), a1.out.trim());

  section('7. ATTACK 2 - edit content AND recompute the hash to hide it');
  writeFileSync(chainPath, forge(original, 0, (e) => { e.summary = 'lies about what happened'; }, true));
  const a2 = attempt(witness(['verify']));
  check('detected', a2.code === 1 && /TAMPERING DETECTED/.test(a2.out), a2.out.trim());
  check('escaped the content-hash check', !/content hash mismatch/.test(a2.out), a2.out.trim());
  check('caught by the signature', /signature invalid/.test(a2.out), a2.out.trim());
  check('indicted the successor entry', /#1: prevHash breaks the chain/.test(a2.out), a2.out.trim());

  section('8. recovery - restore the chain');
  writeFileSync(chainPath, original);
  const rec = attempt(witness(['verify']));
  check('restored chain verifies', rec.code === 0 && /CHAIN INTACT/.test(rec.out), rec.out.trim());

  section('9. regression tracking');
  const reg = attempt(witness(['regress', '--of', '0']));
  const after = readChain();
  check('regression recorded', reg.code === 0 && after.length === 3 && after[2].regressionOf === 0, reg.out.trim());
  check('chain still verifies after a regression', attempt(witness(['verify'])).code === 0);

  section('10. report generation');
  attempt(witness(['report']));
  const md = existsSync(join(repo, '.witness/report.md')) ? readFileSync(join(repo, '.witness/report.md'), 'utf8') : '';
  check('report written', md.length > 0);
  check('report says VERIFIED', /Integrity: \*\*VERIFIED\*\*/.test(md));
  check('report names the signing key', /Signing key: `[0-9a-f]{16}`/.test(md), (md.match(/Signing key:.*/) || [''])[0]);
  check('report lists both commit messages', /first change/.test(md) && /second change/.test(md));
  check('report does not leak the private key', !/privateKey/.test(md));

  section('11. fail-closed - a missing tool must block the commit');
  const saveBin = git(['config', 'witness.bin']).out.trim();
  check('pinned path is readable back', saveBin.length > 0, 'got: ' + JSON.stringify(saveBin));
  git(['config', 'witness.bin', join(repo, 'does-not-exist.mjs')]);
  writeFileSync(join(repo, 'blocked.js'), 'export const w = 4;\n');
  git(['add', 'blocked.js']);
  const blocked = attempt(git(['commit', '-q', '-m', 'should be refused']));
  check('commit is refused', blocked.code !== 0, 'exit=' + blocked.code);
  check('refusal names the fix', /witness\.bin/.test(blocked.out), blocked.out.trim());
  check('the commit did not land', !git(['log', '--oneline']).out.includes('should be refused'));
  git(['config', 'witness.bin', saveBin]);

  // Custody is tested last because destroying the key is irreversible within the
  // run -- everything above needs the ability to sign.
  section('12. custody - verification with the private key destroyed');
  const pubBefore = readFileSync(join(repo, '.witness/pubkey.json'), 'utf8');
  const signed = readFileSync(chainPath, 'utf8');
  rmSync(keyDir, { recursive: true, force: true });
  check('the key really was outside the repo', !existsSync(keyDir) && existsSync(chainPath));
  const nokey = attempt(witness(['verify']));
  check('verifies with the private key destroyed', nokey.code === 0 && /CHAIN INTACT/.test(nokey.out), nokey.out.trim());
  check('the public key is untouched', readFileSync(join(repo, '.witness/pubkey.json'), 'utf8') === pubBefore);
  writeFileSync(chainPath, forge(signed, 0, (e) => { e.summary = 'lies again'; }, true));
  const nokeyBad = attempt(witness(['verify']));
  check('still catches a rehashed forgery with no key', nokeyBad.code === 1 && /signature invalid/.test(nokeyBad.out), nokeyBad.out.trim());

  // A signed chain whose key has vanished must not be papered over by quietly
  // minting a fresh keypair, which would orphan every existing signature.
  const refused = attempt(witness(['init']));
  check('init refuses to orphan a signed chain',
    refused.code === 1 && /refusing to generate a new signing key/.test(refused.out),
    'exit=' + refused.code + ' ' + refused.out.trim());
  check('refusal explains the recovery', /--force-new-key/.test(refused.out), refused.out.trim());
  check('the refused init did not overwrite the public key',
    readFileSync(join(repo, '.witness/pubkey.json'), 'utf8') === pubBefore);

} catch (e) {
  fail++;
  console.log('\n  HARNESS ERROR: ' + String(e.stderr || e.message));
} finally {
  for (const d of [repo, keyDir]) { try { rmSync(d, { recursive: true, force: true }); } catch {} }
}

console.log('\n' + '='.repeat(58));
console.log('  witness test-all: ' + pass + ' passed, ' + fail + ' failed');
console.log('='.repeat(58));
process.exit(fail ? 1 : 0);
