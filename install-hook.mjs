#!/usr/bin/env node
// install-hook.mjs - install the witness commit-msg hook into a git repo.
//
//   node install-hook.mjs [repo-path]     (default: current directory)
//
// Copies hooks/commit-msg into <repo>/.git/hooks/, marks it executable, pins the
// tool path in git config, removes any superseded pre-commit hook, and checks
// the thing that silently breaks a witness chain: a private key being committed.

import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, unlinkSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const target = resolve(process.argv[2] || process.cwd());
// `git config <name>` exits non-zero when the key is simply absent, which is the
// normal case for a first install. Read it without treating that as an error.
const gitTry = (args) => { try { return execFileSync('git', args, { cwd: target, encoding: 'utf8' }).trim(); } catch { return ''; } };
const git = (args) => execFileSync('git', args, { cwd: target, encoding: 'utf8' }).trim();

const SRC = fileURLToPath(new URL('./hooks/commit-msg', import.meta.url));
const CLI = fileURLToPath(new URL('./witness.mjs', import.meta.url));
const APP = fileURLToPath(new URL('./app.mjs', import.meta.url));
const UI = fileURLToPath(new URL('./ui.html', import.meta.url));

console.log('witness: installing into ' + target);

let hooksDir;
try {
  hooksDir = git(['rev-parse', '--git-path', 'hooks']);
} catch {
  console.error('witness: not a git repository: ' + target);
  process.exit(1);
}
// git prints this relative (".git/hooks") when the hooks dir is inside the work
// tree, so it must be made absolute or every path below resolves against our own
// cwd rather than the target repo. Refuse anything pointing outside the repo.
const absHooks = resolve(target, hooksDir);
hooksDir = absHooks.startsWith(resolve(target) + sep) ? absHooks : join(target, '.git', 'hooks');

function install(name, from, marker) {
  const dest = join(hooksDir, name);
  if (existsSync(dest)) {
    const current = readFileSync(dest, 'utf8');
    if (current.includes(marker)) {
      console.log('witness: replacing the existing witness ' + name);
    } else {
      const backup = dest + '.witness-backup';
      copyFileSync(dest, backup);
      console.log('witness: a non-witness ' + name + ' was there. Backed up to\n  ' + backup);
    }
  }
  copyFileSync(from, dest);
  try { chmodSync(dest, 0o755); } catch { /* Windows: git runs hooks through sh regardless */ }
  console.log('witness: installed ' + dest);
}

// Retire the earlier pre-commit hook: it could only ever record a diffstat
// guess, because the commit message does not exist at pre-commit time.
const legacy = join(hooksDir, 'pre-commit');
if (existsSync(legacy) && readFileSync(legacy, 'utf8').includes('witness pre-commit hook')) {
  unlinkSync(legacy);
  console.log('witness: removed the superseded pre-commit hook (see hooks/commit-msg)');
}

install('commit-msg', SRC, 'witness commit-msg hook');

// Pin this install as the tool the hook should use. The hook's cwd is the repo
// root, so this must be an ABSOLUTE path -- a relative one would resolve
// against the repo instead of the product install and silently fail every
// commit.
try {
  execFileSync('git', ['config', 'witness.bin', CLI], { cwd: target, stdio: 'pipe' });
  console.log('witness: pinned witness.bin -> ' + CLI);
} catch (e) {
  console.log('witness: could not set witness.bin (' + e.message.split('\n')[0] + ')');
  console.log('  set it by hand:  git config witness.bin "' + CLI + '"');
}

// Pin the signing-key id, so a clone that adopts this key (via WITNESS_KEY_DIR
// or by regenerating from the same id) records against the same identity instead
// of minting a new one for the same chain. NOTE: .git/config is NOT copied by
// git clone, so this is local; what actually travels to a clone is the vendored
// tools/ directory, and a contributor gets the id from the public key there.
try {
  const existing = gitTry(['config', 'witness.keyId']);
  if (existing) {
    console.log('witness: witness.keyId already set -> ' + existing);
  } else if (existsSync(join(target, '.witness/pubkey.json'))) {
    const kid = JSON.parse(readFileSync(join(target, '.witness/pubkey.json'), 'utf8')).keyId;
    execFileSync('git', ['config', 'witness.keyId', kid], { cwd: target, stdio: 'pipe' });
    console.log('witness: pinned witness.keyId -> ' + kid);
  } else {
    console.log('witness: no chain here yet, key id will be pinned on the first commit');
  }
} catch (e) {
  console.log('witness: could not pin witness.keyId (' + e.message.split('\n')[0] + ')');
}

// The chain and the public key belong in the repo. The private key does not --
// witness now stores it outside the tree, but older chains may still carry one.
const gi = join(target, '.gitignore');
const want = ['.witness/keys.json', '.witness/*.bak'];
if (!existsSync(gi)) {
  writeFileSync(gi, want.join('\n') + '\n');
  console.log('witness: created .gitignore (excludes any legacy in-repo signing key)');
} else {
  const have = readFileSync(gi, 'utf8');
  const missing = want.filter((l) => !have.includes(l));
  if (missing.length) {
    appendFileSync(gi, '\n' + missing.join('\n') + '\n');
    console.log('witness: added to .gitignore: ' + missing.join(', '));
  }
}

// Vendor the tool into the repo so a clone is self-sufficient. git does not copy
// .git/hooks or .git/config into a new clone, so without this a contributor
// would have no hook and their commits would go unrecorded -- provenance
// stopping silently at the fork, which is the exact failure this tool exists
// to prevent. The copy is read-only in practice: the hook prefers git config,
// then this, and only then the pinned absolute path.
const vendored = join(target, 'tools', 'witness');
try {
  mkdirSync(vendored, { recursive: true });
  copyFileSync(CLI, join(vendored, 'witness.mjs'));
  copyFileSync(SRC, join(vendored, 'commit-msg'));
  copyFileSync(APP, join(vendored, 'app.mjs'));
  copyFileSync(UI, join(vendored, 'ui.html'));
  console.log('witness: vendored the tool at tools/witness/ (so clones are self-sufficient)');
} catch (e) {
  console.log('witness: could not vendor the tool (' + e.message.split('\n')[0] + ')');
  console.log('  clones will need:  node install-hook.mjs .');
}

console.log('');
console.log('Now:');
console.log('  git add .witness/ tools/ && git commit   # commit the chain + vendored tool');
console.log('  WITNESS_SKIP=1 git commit ...     # escape hatch, records nothing');
console.log('  node "' + CLI + '" verify        # check the chain');
console.log('  node "' + CLI + '" report        # write .witness/report.md');
console.log('  node "' + APP + '"           # open the local dashboard');
