#!/usr/bin/env node
// witness - tamper-evident provenance for agent-driven code changes.
// Zero dependencies. Requires Node >= 20 (uses node:crypto ed25519).
//
// Key custody: the private key lives OUTSIDE the repository, by default in
// ~/.witness/keys/. Only the public key is written into .witness/, so holding
// the repo (or read access to it) does not grant the ability to re-sign
// history. Verification needs the public key alone.

import { createHash, generateKeyPairSync, sign, verify, createPrivateKey, createPublicKey } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

const DIR = '.witness';
const CHAIN = join(DIR, 'chain.jsonl');
const PUBKEY = join(DIR, 'pubkey.json');
const LEGACY_KEYS = join(DIR, 'keys.json'); // pre-custody-fix layout, still readable
const REPORT = join(DIR, 'report.md');
const GENESIS = '0'.repeat(64);

const canon = (o) =>
  Object.keys(o).sort().reduce((a, k) => { a[k] = o[k]; return a; }, {});
const sha = (s) => createHash('sha256').update(s).digest('hex');
const now = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
const repoRoot = () => resolve(process.cwd());
// The key store is keyed by a caller-supplied id, not by the absolute repo
// path. Path-derived ids meant that cloning a repo -- which necessarily happens
// at a different path -- produced a key that did not exist, so provenance
// silently stopped at the fork. An explicit id travels with the key instead;
// the path is kept only as a human-readable label.
const keyId = () => process.env.WITNESS_KEY_ID || sha(repoRoot()).slice(0, 16);
const keyDirDefault = () => join(homedir(), '.witness', 'keys');
const keyFile = () =>
  join(process.env.WITNESS_KEY_DIR || keyDirDefault(), keyId() + '.json');

function ensureDir() {
  if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });
}

function readPriv() {
  const p = keyFile();
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

function init() {
  ensureDir();
  const p = keyFile();
  let k = readPriv();
  let fresh = false;
  let migrated = false;

  if (!k && existsSync(LEGACY_KEYS)) {
    // Adopt the key that already signed this chain. Generating a fresh keypair
    // here would look correct and silently invalidate every existing entry,
    // because verify() reads pubkey.json and the old signatures were made with
    // the old key.
    const old = JSON.parse(readFileSync(LEGACY_KEYS, 'utf8'));
    k = {
      keyId: keyId(),
      repo: repoRoot(),
      publicKey: old.publicKey,
      privateKey: old.privateKey,
      createdAt: old.createdAt || now(),
    };
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(k, null, 2));
    try { chmodSync(p, 0o600); } catch { /* best effort; POSIX-only meaningful */ }
    migrated = true;
  } else if (!k) {
    // A chain exists but its signing key is gone. Generating a fresh keypair
    // here would look like a clean init while silently making every existing
    // signature unverifiable -- the same corruption the migration branch above
    // exists to prevent. Refuse unless the caller insists.
    if (existsSync(CHAIN) && !process.argv.includes('--force-new-key') && !process.argv.includes('--new-identity')) {
      console.error('witness: refusing to generate a new signing key.');
      console.error('  A signed chain already exists in this repo, but its key is not in');
      console.error('  the key store (' + p + ').');
      console.error('');
      console.error('  To keep this chain signed the way it already is, recover the key');
      console.error('  from whoever holds it, or point witness at it:');
      console.error('    set WITNESS_KEY_DIR to where the key lives');
      console.error('');
      console.error('  To add your own key as an additional signer (a new identity, not a');
      console.error('  forgery -- existing entries keep their original signatures):');
      console.error('    witness init --new-identity');
      console.error('');
      console.error('  To discard the history and start over:');
      console.error('    witness init --force-new-key   (then delete ' + CHAIN + ')');
      process.exit(1);
    }
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    k = {
      keyId: keyId(),
      repo: repoRoot(),
      publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex'),
      createdAt: now(),
    };
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(k, null, 2));
    try { chmodSync(p, 0o600); } catch { /* best effort; POSIX-only meaningful */ }
    fresh = true;
  }

  // A chain can be signed by more than one key -- upstream, a teammate, CI.
  // pubkey.json is a registry, not a single key, so verification keeps working
  // across identities. It is written (not appended) only when the repo has no
  // registry yet or the key is the one it already knows.
  const incoming = { keyId: k.keyId, publicKey: k.publicKey, createdAt: k.createdAt };
  let registry = { keys: [incoming] };
  if (existsSync(PUBKEY)) {
    try {
      const old = JSON.parse(readFileSync(PUBKEY, 'utf8'));
      const keys = Array.isArray(old.keys) ? old.keys : (old.publicKey ? [old] : []);
      const known = keys.find((x) => x.keyId === k.keyId);
      if (known) known.publicKey = k.publicKey;
      else keys.push(incoming);
      registry = { keys };
    } catch { registry = { keys: [incoming] }; }
  }
  writeFileSync(PUBKEY, JSON.stringify(registry, null, 2));

  console.log('witness: ' + (migrated ? 'migrated the in-repo key to the external key store'
    : fresh ? 'initialized' : 'already initialized'));
  console.log('  signing key : ' + p + '   <- outside the repo, mode 600');
  console.log('  public key  : ' + PUBKEY + '   <- safe to commit');
  if (registry.keys.length > 1) {
    console.log('  this chain is signed by ' + registry.keys.length +
                ' keys: ' + registry.keys.map((x) => x.keyId).join(', '));
    console.log('  Commit the updated ' + PUBKEY + ' so others can verify all of them.');
  }
  if (existsSync(LEGACY_KEYS)) {
    console.log('');
    console.warn('witness: WARNING - a private key is still inside the repo at ' + LEGACY_KEYS);
    console.warn('  It is still honoured for backwards compatibility. Move it out:');
    console.warn('    mv "' + LEGACY_KEYS + '" "' + p + '"   (then commit the deletion)');
  }
}

function loadPriv() {
  if (existsSync(LEGACY_KEYS)) {
    const k = JSON.parse(readFileSync(LEGACY_KEYS, 'utf8'));
    return createPrivateKey({ key: Buffer.from(k.privateKey, 'hex'), format: 'der', type: 'pkcs8' });
  }
  const k = readPriv();
  if (!k) {
    // This is the state every fresh clone is in: the chain and public key
    // travel with the repo, the signing key does not. Say exactly that, and
    // how to join, rather than a bare "run init".
    console.error('witness: no signing key for this repo (looked for ' + keyFile() + ').');
    if (existsSync(CHAIN)) {
      console.error('  This repo already has a signed chain, so the key that signed it is');
      console.error('  not in this key store. Options:');
      console.error('    - get that key from whoever holds it, and drop it at the path above');
      console.error('    - set WITNESS_KEY_DIR to where the key lives');
      console.error('    - record under your own key instead (a new identity, not a forgery):');
      console.error('        witness init --new-identity');
    } else {
      console.error('  Fix:  witness init');
    }
    process.exit(1);
  }
  return createPrivateKey({ key: Buffer.from(k.privateKey, 'hex'), format: 'der', type: 'pkcs8' });
}

// Verification deliberately reads only public keys. If this still works with
// the private key deleted, custody is real rather than claimed.
function loadPub() {
  if (existsSync(PUBKEY)) {
    const k = JSON.parse(readFileSync(PUBKEY, 'utf8'));
    // A registry of keys: any one of them may have signed a given entry, so
    // verification tries all of them. Supports both the current {keys:[...]}
    // shape and the original single-key file.
    const list = Array.isArray(k.keys) ? k.keys : [k];
    return list
      .filter((x) => x && x.publicKey)
      .map((x) => ({ pub: createPublicKey({ key: Buffer.from(x.publicKey, 'hex'), format: 'der', type: 'spki' }), keyId: x.keyId }));
  }
  const k = readPriv() || (existsSync(LEGACY_KEYS) ? JSON.parse(readFileSync(LEGACY_KEYS, 'utf8')) : null);
  if (!k) { console.error('witness: no public key. run: witness init'); process.exit(1); }
  return [{ pub: createPublicKey({ key: Buffer.from(k.publicKey, 'hex'), format: 'der', type: 'spki' }), keyId: k.keyId }];
}

function readChain() {
  if (!existsSync(CHAIN)) return [];
  return readFileSync(CHAIN, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

function body(e) {
  const { hash, signature, ...rest } = e;
  return JSON.stringify(canon(rest));
}
const entryHash = (e) => sha(body(e));

function append(entry) {
  ensureDir();
  const priv = loadPriv();
  const prev = readChain();
  const full = {
    ...entry,
    index: prev.length,
    timestamp: entry.timestamp || now(),
    prevHash: prev.length ? prev[prev.length - 1].hash : GENESIS,
  };
  full.hash = entryHash(full);
  full.signature = sign(null, Buffer.from(full.hash, 'hex'), priv).toString('hex');
  appendFileSync(CHAIN, JSON.stringify(full) + '\n');
  return full;
}

function record(argv) {
  const i = argv.indexOf('--actor');
  const s = argv.indexOf('--summary');
  const f = argv.indexOf('--files');
  const e = append({
    action: 'commit',
    actor: i >= 0 ? argv[i + 1] : 'unknown',
    summary: s >= 0 ? argv[s + 1] : '(no summary)',
    files: f >= 0 ? argv[f + 1].split(',').map((x) => x.trim()).filter(Boolean) : [],
    regressionOf: null,
  });
  console.log('witness: recorded #' + e.index + ' ' + e.hash.slice(0, 12));
}

function regress(argv) {
  const o = argv.indexOf('--of');
  if (o < 0) { console.error('usage: witness regress --of <index>'); process.exit(1); }
  const target = Number(argv[o + 1]);
  if (!Number.isInteger(target) || !readChain()[target]) {
    console.error('witness: no entry at index ' + target); process.exit(1);
  }
  const e = append({ action: 'regression', actor: 'witness', summary: 'regression of #' + target,
    files: [], regressionOf: target });
  console.log('witness: regression #' + e.index + ' -> #' + target);
}

function verifyChain() {
  const chain = readChain();
  if (!chain.length) return { ok: true, checked: 0, problems: [], signers: [] };
  const pubs = loadPub();
  const problems = [];
  const signedBy = [];

  chain.forEach((e, i) => {
    if (e.index !== i) problems.push('#' + i + ': index field is ' + e.index);
    const expectedPrev = i ? chain[i - 1].hash : GENESIS;
    if (e.prevHash !== expectedPrev) problems.push('#' + i + ': prevHash breaks the chain');
    if (entryHash(e) !== e.hash) problems.push('#' + i + ': content hash mismatch (entry was edited)');
    // An entry may have been signed by any key in the registry, so it is valid
    // if ANY of them verifies it. Recording which one did makes a multi-signer
    // chain auditable rather than just "valid".
    const sig = Buffer.from(e.signature, 'hex');
    const h = Buffer.from(e.hash, 'hex');
    const signer = pubs.find(({ pub }) => verify(null, h, pub, sig));
    if (!signer) {
      problems.push('#' + i + ': signature invalid (no key in ' + PUBKEY + ' signed this entry)');
    } else if (signer.keyId) {
      signedBy[i] = signer.keyId;
    }
  });

  return {
    ok: problems.length === 0,
    checked: chain.length,
    problems,
    signedBy,
    signers: [...new Set(signedBy.filter(Boolean))],
  };
}

function cmdVerify() {
  const r = verifyChain();
  // --json is for machines (the dashboard in app.mjs, and any CI that wants
  // structure rather than a string to regex). The human output stays as it was:
  // two consumers parsing the same sentences is how tools drift apart.
  if (process.argv.includes('--json')) {
    let keys = [];
    try { keys = loadPub(); } catch { /* uninitialised repo */ }
    const chain = readChain();
    console.log(JSON.stringify({
      ok: r.ok,
      checked: r.checked,
      problems: r.problems,
      signers: r.signers || [],
      keys: keys.map((k) => k.keyId).filter(Boolean),
      chain: chain.map((e) => ({
        index: e.index,
        action: e.action,
        actor: e.actor,
        summary: e.summary,
        files: e.files || [],
        regressionOf: e.regressionOf,
        timestamp: e.timestamp,
        hash: e.hash,
        prevHash: e.prevHash,
        signature: e.signature,
        // Which committed public key signed THIS entry, so the UI can show it
        // per row rather than only as a chain-wide total.
        signedBy: (r.signedBy && r.signedBy[e.index]) || null,
      })),
    }, null, 2));
    process.exit(r.ok ? 0 : 1);
  }
  console.log('witness: ' + r.checked + ' entries checked - ' + (r.ok ? 'CHAIN INTACT' : 'TAMPERING DETECTED'));
  if (r.signers && r.signers.length > 1) {
    console.log('  signed by ' + r.signers.length + ' keys: ' + r.signers.join(', '));
  }
  r.problems.forEach((p) => console.log('  ! ' + p));
  process.exit(r.ok ? 0 : 1);
}

function cmdReport() {
  const chain = readChain();
  const v = verifyChain();
  let keys = [];
  try { keys = loadPub(); } catch { /* uninitialised repo */ }
  const kids = keys.map((k) => k.keyId).filter(Boolean);
  const regressions = chain.filter((e) => e.action === 'regression');
  const touched = new Set(chain.flatMap((e) => e.files || []));

  const rows = chain.map((e) =>
    '| ' + e.index + ' | ' + e.timestamp + ' | ' + e.actor + ' | ' + e.action +
    ' | ' + (e.summary || '-').replace(/\|/g, '\\|') +
    ' | ' + ((e.files || []).length || '-') + ' | ' + e.hash.slice(0, 12) + ' |');

  const md = [
    '# Change provenance report', '',
    '- Generated: ' + now(),
    '- Signing key' + (kids.length > 1 ? 's' : '') + ': ' +
      (kids.length ? kids.map((k) => '`' + k + '`').join(', ') : '`unknown`') +
      ' (public keys in `.witness/pubkey.json`; private keys held outside the repo)',
    '- Entries: ' + chain.length,
    '- Integrity: **' + (v.ok ? 'VERIFIED' : 'FAILED') + '** (Ed25519 chain, ' + v.checked + ' entries checked)',
    '- Regressions recorded: ' + regressions.length,
    '- Distinct files touched: ' + touched.size, '',
    '## Chain', '',
    '| # | Timestamp | Actor | Action | Summary | Files | Hash |',
    '|---|---|---|---|---|---|---|',
    ...rows, '',
    v.ok ? '' : '## Integrity problems\n' + v.problems.map((p) => '- ' + p).join('\n'),
  ].join('\n');

  writeFileSync(REPORT, md);
  console.log('witness: report written to ' + REPORT);
}

function selftest() {
  const tmp = join(process.cwd(), '.witness-selftest');
  const prevCwd = process.cwd();
  const prevKeyDir = process.env.WITNESS_KEY_DIR;
  const keyDir = join(tmp, 'keys');
  if (existsSync(tmp)) rmSync(tmp, { recursive: true, force: true });
  mkdirSync(keyDir, { recursive: true });

  let pass = 0, fail = 0;
  const check = (name, cond) => {
    if (cond) { pass++; console.log('  ok   ' + name); }
    else { fail++; console.log('  FAIL ' + name); }
  };

  try {
    process.chdir(tmp);
    process.env.WITNESS_KEY_DIR = keyDir;
    init();
    check('init writes the private key outside the repo',
      existsSync(keyFile()) && !existsSync(join(DIR, 'keys.json')));
    check('init writes only a public key into the repo',
      existsSync(PUBKEY) && !existsSync(LEGACY_KEYS));

    append({ action: 'commit', actor: 'a1', summary: 'first',  files: ['x.ts'], regressionOf: null });
    append({ action: 'commit', actor: 'a2', summary: 'second', files: ['y.ts'], regressionOf: null });
    check('clean chain verifies', verifyChain().ok);

    const lines = () => readFileSync(CHAIN, 'utf8').trim().split('\n');
    const save = (arr) => writeFileSync(CHAIN, arr.join('\n') + '\n');
    const pristine = lines();

    // Attack 1: edit the content, leave hash and signature alone. The stored
    // hash no longer matches the content it claims to cover.
    const lazy = JSON.parse(pristine[0]);
    lazy.summary = 'quietly swapped';
    save([JSON.stringify(lazy), pristine[1]]);
    const v1 = verifyChain();
    check('attack 1 (content edit) is detected', !v1.ok);
    check('attack 1 caught by content hash', v1.problems.some((p) => p.includes('content hash')));
    save(pristine);

    // Attack 2: edit the content AND recompute the hash to hide it, leaving the
    // original signature. The content hash now matches, so only the signature
    // can catch this -- and the attacker has no key to forge one with.
    const careful = JSON.parse(pristine[0]);
    careful.summary = 'quietly swapped';
    careful.hash = entryHash(careful);
    save([JSON.stringify(careful), pristine[1]]);
    const v2 = verifyChain();
    check('attack 2 (rehashed edit) is detected', !v2.ok);
    check('attack 2 escapes the content hash check',
      !v2.problems.some((p) => p.includes('content hash mismatch')));
    check('attack 2 caught by signature', v2.problems.some((p) => p.includes('signature invalid')));
    save(pristine);

    // Custody: with the signing key destroyed, a third party holding only the
    // committed .witness/ directory must still be able to check every signature.
    const priv = readPriv();
    rmSync(keyFile());
    check('verification works with the private key deleted', verifyChain().ok);
    check('verification still catches tampering without the private key', (() => {
      const f = JSON.parse(pristine[0]);
      f.summary = 'swapped again';
      save([JSON.stringify(f), pristine[1]]);
      const v = verifyChain();
      save(pristine);
      return !v.ok;
    })());
    check('the deleted key really was the only copy', !existsSync(keyFile()) && priv !== null);

    // A second signer. A fresh clone has the chain and the public keys but not
    // the private keys, so "record under my own key" has to be a real, honest
    // path -- not a way to overwrite someone else's history.
    {
      const prevId = process.env.WITNESS_KEY_ID;
      const prevArgs = process.argv;
      process.env.WITNESS_KEY_ID = 'secondsigner';
      // This is the documented second-signer flow, and the one a fresh clone
      // actually runs: adopt the committed registry, then add a key of your own.
      process.argv = [prevArgs[0], prevArgs[1], 'init', '--new-identity'];
      init();
      process.argv = prevArgs;

      const reg = JSON.parse(readFileSync(PUBKEY, 'utf8'));
      check('the registry kept the first key alongside the new one',
        reg.keys.length === 2 && reg.keys[0].keyId !== 'secondsigner', JSON.stringify(reg.keys.map((k) => k.keyId)));
      check('the second key was written outside the repo',
        existsSync(keyFile()) && !existsSync(join(DIR, 'keys.json')));

      append({ action: 'commit', actor: 'b', summary: 'from a second signer', files: ['z.ts'], regressionOf: null });
      const v = verifyChain();
      check('a chain signed by two keys still verifies', v.ok, v.problems.join('; '));
      check('both signers are reported', v.signers.length === 2, v.signers.join(','));
      check('the new entry is attributed to the second key', v.signedBy[2] === 'secondsigner');
      check('adding a key did not disturb the earlier entries', v.signedBy[0] === v.signedBy[1]);

      // A registry that does not contain the signing key must not verify.
      writeFileSync(PUBKEY, JSON.stringify({ keys: [reg.keys[0]] }, null, 2));
      const stripped = verifyChain();
      check('an entry signed by a key absent from the registry fails',
        !stripped.ok && stripped.problems.some((p) => p.includes('signature invalid')),
        stripped.problems.join('; '));
      writeFileSync(PUBKEY, JSON.stringify(reg, null, 2));

      // init must not mint a new key for a chain it can already sign.
      process.argv = [prevArgs[0], prevArgs[1], 'init'];
      init();
      process.argv = prevArgs;
      check('re-running init did not add a third key',
        JSON.parse(readFileSync(PUBKEY, 'utf8')).keys.length === 2);

      rmSync(keyFile());
      if (prevId === undefined) delete process.env.WITNESS_KEY_ID;
      else process.env.WITNESS_KEY_ID = prevId;
    }
  } finally {
    process.chdir(prevCwd);
    if (prevKeyDir === undefined) delete process.env.WITNESS_KEY_DIR;
    else process.env.WITNESS_KEY_DIR = prevKeyDir;
    rmSync(tmp, { recursive: true, force: true });
  }

  console.log('\nwitness selftest: ' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
}

const [, , cmd, ...rest] = process.argv;
switch (cmd) {
  case 'init':     init(); break;
  case 'record':   record(rest); break;
  case 'regress':  regress(rest); break;
  case 'verify':   cmdVerify(); break;
  case 'report':   cmdReport(); break;
  case 'selftest': selftest(); break;
  default:
    console.log('witness - tamper-evident provenance for agent changes');
    console.log('');
    console.log('  witness init                        generate signing keypair (key stored outside the repo)');
    console.log('  witness init --force-new-key        start a fresh identity over an orphaned chain');
    console.log('  witness init --new-identity         add another signing key to the existing chain');
    console.log('  witness record --actor A --summary "..." [--files a.ts,b.ts]');
    console.log('  witness regress --of <index>        mark an earlier change as regressed');
    console.log('  witness verify                      check chain integrity (exit 1 on tamper)');
    console.log('  witness report                      write .witness/report.md');
    console.log('  witness selftest                    prove tampering is detected');
}
