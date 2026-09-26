#!/usr/bin/env node
// app.mjs - a local web dashboard for the witness chain.
//
//   node app.mjs                    serve the current directory on :7373
//   node app.mjs /path/to/repo      serve another repository
//   node app.mjs --port 8080        pick a port
//
// Serves exactly one directory (the repo) and binds to 127.0.0.1 only. There is
// no auth, because it is a local view of files you already control. It binds to
// loopback because a provenance tool that leaks its repository over the network
// is a liability. Mutating browser requests are additionally same-origin only:
// loopback binding by itself does not stop another website from attempting a
// cross-origin POST from the user's browser.
//
// Every mutating action goes through a named endpoint, never through a shell
// interpolation of user input. The repo path is resolved once at startup and
// never taken from a request, so no request can point the server at another
// directory.

import { createServer } from 'node:http';
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const CLI = join(HERE, 'witness.mjs');

// ---- arguments -------------------------------------------------------------
const argv = process.argv.slice(2);
const portArg = argv.indexOf('--port');
const PORT = portArg >= 0 ? Number(argv[portArg + 1]) : 7373;
const repoArg = argv.filter((a, i) => !a.startsWith('--') && i !== portArg + 1)[0];
const REPO = resolve(repoArg || process.cwd());

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error('witness app: --port must be an integer from 1 to 65535');
  process.exit(1);
}
if (!existsSync(join(REPO, '.witness'))) {
  console.error('witness app: no .witness/ directory in ' + REPO);
  console.error('  Run this from a repository that uses witness, or pass the path.');
  process.exit(1);
}

// ---- the only two things the UI needs --------------------------------------
// `witness verify --json` is the single source of truth. The app does not
// reimplement hashing, chaining or signature checking: a second implementation
// is a second thing to keep correct, and the two would eventually disagree
// about whether a chain was tampered with. If verify says the chain is intact,
// that is the answer.
function runVerify() {
  const r = spawnSync(process.execPath, [CLI, 'verify', '--json'], {
    cwd: REPO, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  });
  let data;
  try {
    data = JSON.parse(r.stdout);
  } catch {
    return {
      ok: false, checked: 0, problems: ['could not read verify output'], signers: [],
      keys: [], chain: [], _error: (r.stderr || '').trim() || 'no output',
    };
  }
  data._exitCode = r.status;
  return data;
}

function gitInfo() {
  const run = (args) => {
    const r = spawnSync('git', args, { cwd: REPO, encoding: 'utf8' });
    return r.status === 0 ? (r.stdout || '').trim() : '';
  };
  // Map each chain entry to the commit it was written for, so the timeline can
  // show a short sha next to each change. Entry N is the Nth commit the hook
  // recorded, and git's newest-first log is reversed to match.
  const shas = new Map();
  const log = run(['log', '--format=%H']);
  const n = Number(run(['rev-list', '--count', 'HEAD']) || 0);
  const list = log ? log.split('\n') : [];
  for (let i = 0; i < n; i++) shas.set(n - 1 - i, (list[i] || '').slice(0, 7));
  return {
    branch: run(['rev-parse', '--abbrev-ref', 'HEAD']) || '(no commits)',
    head: run(['rev-parse', '--short', 'HEAD']),
    commitCount: n,
    status: run(['status', '--porcelain']),
    remote: run(['remote', 'get-url', 'origin']),
    dirty: run(['status', '--porcelain']).split('\n').filter(Boolean).length,
    shas,
  };
}

function state() {
  const v = runVerify();
  const g = gitInfo();
  const chain = (v.chain || []).map((e) => ({
    ...e,
    sha: g.shas.get(e.index) || null,
  })).reverse(); // newest first
  const regressions = (v.chain || []).filter((e) => e.action === 'regression');
  const files = new Set((v.chain || []).flatMap((e) => e.files || []));
  return {
    repo: REPO,
    ok: v.ok,
    checked: v.checked,
    problems: v.problems || [],
    signers: v.signers || [],
    keys: v.keys || [],
    chain,
    stats: {
      entries: v.checked,
      regressions: regressions.length,
      filesTouched: files.size,
      signers: (v.signers || []).length,
    },
    git: {
      branch: g.branch, head: g.head, commitCount: g.commitCount,
      dirty: g.dirty, remote: g.remote, status: g.status,
    },
    error: v._error || null,
  };
}

// ---- http ------------------------------------------------------------------
const send = (res, code, type, body) => {
  res.writeHead(code, {
    'content-type': type,
    'cache-control': 'no-store',        // a stale integrity verdict is worse than none
    'x-content-type-options': 'nosniff',
  });
  res.end(body);
};
const json = (res, code, obj) => send(res, code, 'application/json', JSON.stringify(obj, null, 2));

function isSameOrigin(req) {
  // A same-origin browser fetch sends Origin. Command-line clients usually do
  // not, so accept an absent header while rejecting origins from other websites.
  const origin = req.headers.origin;
  return !origin || origin === 'http://127.0.0.1:' + PORT || origin === 'http://localhost:' + PORT;
}

// Actions the UI may trigger. Each is a fixed argv; the request body supplies
// only values that go in as separate arguments, never as shell text.
const ACTIONS = {
  verify: () => ({ action: 'verify', result: 'chain re-verified' }),
  report: () => {
    const r = spawnSync(process.execPath, [CLI, 'report'], { cwd: REPO, encoding: 'utf8' });
    if (r.status !== 0) throw new Error((r.stderr || 'report failed').trim());
    return { action: 'report', result: 'wrote .witness/report.md' };
  },
  record: (body) => {
    const summary = String(body.summary || '').slice(0, 200);
    if (!summary) throw new Error('a summary is required');
    const actor = String(body.actor || 'app').slice(0, 80);
    const files = String(body.files || '').split(',').map((s) => s.trim()).filter(Boolean).slice(0, 200);
    const args = [CLI, 'record', '--actor', actor, '--summary', summary];
    if (files.length) args.push('--files', files.join(','));
    const r = spawnSync(process.execPath, args, { cwd: REPO, encoding: 'utf8' });
    if (r.status !== 0) throw new Error((r.stderr || 'record failed').trim());
    return { action: 'record', result: (r.stdout || '').trim() };
  },
  regress: (body) => {
    const of = String(body.of || '').trim();
    if (!/^\d+$/.test(of)) throw new Error('regress needs the index of the entry, as a number');
    const r = spawnSync(process.execPath, [CLI, 'regress', '--of', of], { cwd: REPO, encoding: 'utf8' });
    if (r.status !== 0) throw new Error((r.stderr || 'regress failed').trim());
    return { action: 'regress', result: (r.stdout || '').trim() };
  },
};

const server = createServer((req, res) => {
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch { return send(res, 400, 'text/plain', 'bad request'); }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    return send(res, 200, 'text/html; charset=utf-8', readFileSync(join(HERE, 'ui.html'), 'utf8'));
  }
  if (url.pathname === '/api/state') return json(res, 200, state());

  if (url.pathname === '/api/action' && req.method === 'POST') {
    if (!isSameOrigin(req)) return json(res, 403, { ok: false, error: 'cross-origin requests are not allowed' });
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 1e6) req.destroy(); });
    req.on('end', () => {
      let body = {};
      try { body = raw ? JSON.parse(raw) : {}; } catch { return json(res, 400, { ok: false, error: 'invalid JSON' }); }
      const fn = ACTIONS[String(body.action || '')];
      if (!fn) return json(res, 400, { ok: false, error: 'unknown action: ' + String(body.action).slice(0, 40) });
      try {
        const out = fn(body);
        json(res, 200, { ok: true, ...out, state: state() });
      } catch (e) {
        json(res, 400, { ok: false, error: String(e.message || e) });
      }
    });
    return;
  }
  send(res, 404, 'text/plain', 'not found');
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error('witness app: port ' + PORT + ' is already in use.');
    console.error('  pick another:  node app.mjs --port 8080');
  } else {
    console.error('witness app: ' + e.message);
  }
  process.exit(1);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('  witness  ' + REPO);
  console.log('  http://localhost:' + PORT);
  console.log('');
  console.log('  bound to 127.0.0.1 only. Ctrl-C to stop.');
  console.log('');
});

process.on('SIGINT', () => { console.log('\nwitness app: stopped'); process.exit(0); });
