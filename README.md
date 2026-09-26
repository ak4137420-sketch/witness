# witness

**Tamper-evident provenance for agent-made changes.**

An AI agent can tell you what it did. It cannot prove it. `witness` is a git
hook that records every commit into an append-only, hash-chained, Ed25519-signed
ledger, so the record of *what changed and why* survives after the agent's
transcript is gone — and survives being edited.

Zero dependencies. `node:crypto` only. Node ≥ 20.

```
git commit -m "refactor the retry backoff"   →  hook appends a signed entry
node witness.mjs verify                      →  CHAIN INTACT
```

---

## Contents

- [Why this exists](#why-this-exists)
- [The threat model](#the-threat-model)
- [How it works](#how-it-works)
- [Install](#install)
- [Commands](#commands)
- [Key custody](#key-custody)
- [Multiple signers](#multiple-signers)
- [Working in a clone](#working-in-a-clone)
- [Environment variables](#environment-variables)
- [Testing](#testing)
- [Files](#files)
- [Limitations](#limitations-read-this)
- [License](#license)

---

## Why this exists

Agent output is unverifiable by construction. The agent wrote the code *and*
wrote the commit message *and* can re-edit both before you look. Git's own
integrity guarantee stops at the tree: git will happily record a lie, and it
will happily let you rewrite one.

`witness` adds a second, independent record that is not part of the commit and
not rewritable without a private key. Every commit is chained to the one
before it, so a change made anywhere in history is detectable anywhere in
history — not just the most recent commit.

It is built for the case where **the thing you don't fully trust is the author
of the change**, including when that author is you, later, on a bad day.

---

## The threat model

Two realistic attacks, and what stops each.

### Attack 1 — edit the content, keep the hashes

Someone (or some agent) edits a line in the recorded summary or file list.

```
entry.summary changed: "fix the leak" → "no change needed"
```

**Caught by the content hash.** Each entry stores `hash` = SHA-256 over its own
canonical body. Change the body and the hash no longer matches.

```
witness: 4 entries checked - TAMPERING DETECTED
  #2: content hash mismatch (the entry text does not match its own hash)
```

This is the cheap attack. It is caught by the first line of verification.

### Attack 2 — edit the content *and* recompute the hash

The attacker knows the scheme. They edit the summary and recompute `hash` to
match. The content-hash check now passes.

```
{ "summary": "no change needed", "hash": "<recomputed>", "signature": "<untouched>" }
```

**Caught by the signature.** `signature` is Ed25519 over the hash bytes. The
attacker has no private key, so no edit to the hash can produce a matching
signature.

```
  #2: signature invalid (no key in .witness/pubkey.json signed this entry)
```

Because the entry is also chained, the forgery cascades forward:

```
  #2: signature invalid ...
  #3: prevHash breaks the chain (this entry does not follow the one before it)
```

Editing entry 0 does not just damage entry 0. It invalidates every entry after
it, which is what makes partial repair pointless.

### What it does *not* stop

A signer who holds the private key can delete `chain.jsonl` and re-sign the
whole thing from scratch. The result verifies perfectly — it is a different,
consistent, self-signed history. See
[Limitations](#limitations-read-this); the fix is an external anchor, not more
hashing.

---

## How it works

### The chain

`.witness/chain.jsonl` — one JSON object per line, append-only:

```json
{
  "action": "commit",
  "actor": "claude-opus",
  "summary": "fix retry backoff to be exponential",
  "files": ["src/retry.mjs"],
  "regressionOf": null,
  "index": 0,
  "timestamp": "2026-09-26T11:37:07Z",
  "prevHash": "0000…0000",
  "hash": "c45835db4753bfb02…",
  "signature": "b3fbb98c0daa116d…"
}
```

- `prevHash` — the previous entry's `hash`. Entry 0 uses 64 zeros.
- `hash` — SHA-256 of the canonical body: keys sorted, `hash` and `signature`
  excluded. This makes the hash independent of JSON key order.
- `signature` — Ed25519 over the hash bytes, hex.

Verification walks the file once, recomputing every hash, checking every
signature, and checking each `prevHash` against the entry before it.

### Actions

| Action | Meaning |
|---|---|
| `commit` | a commit was recorded by the hook |
| `regression` | a later change reverted an earlier one; carries `regressionOf: <index>` |

Regressions are first-class rather than invisible. A project where the agent
fixes a bug that it introduced last week is a project that should be able to say
so numerically. `witness regress --of 3` records that, and the report counts it.

### The `commit-msg` hook, not `pre-commit`

The hook is installed as `commit-msg`, deliberately.

At `pre-commit` time the commit message **does not exist yet**. A pre-commit
hook can only guess at intent from a diffstat — "8 files changed" is not why the
change was made. `commit-msg` runs *after* git has the final message, so the
chain stores the author's actual stated intent. The whole point of the tool is
the `summary` field; recording a guess instead of the real thing would make it
useless.

`install-hook.mjs` removes a superseded `pre-commit` hook if it finds one.

### The hook fails closed

If recording fails, **the commit is refused.** A provenance tool that silently
skips entries is worse than no provenance tool, because the gap is invisible —
you would look at a chain that verifies and wrongly conclude nothing was
skipped. So every failure path exits non-zero with an explanation.

This is why the hook also treats a *missing* tool as an error rather than
falling through to a different one. Quietly recording your provenance with an
unvetted copy of the tool is exactly the substitution this exists to prevent.

### The escape hatch is loud

```bash
WITNESS_SKIP=1 git commit -m "wip"
# witness: WITNESS_SKIP=1, nothing recorded
```

Bypassing is possible — it always is, the key holder can always do it — but it
prints what it did. You cannot skip silently. Merge and squash commits are
likewise not recorded: they are not authorship events, and recording them would
make every merge look like new work.

---

## Install

```bash
git clone <this repo>
cd witness
node install-hook.mjs /path/to/your/project
```

The installer:

1. copies `hooks/commit-msg` into `<repo>/.git/hooks/`;
2. pins the absolute tool path in `git config witness.bin`;
3. pins the signing key id in `git config witness.keyId`;
4. removes a superseded `pre-commit` hook;
5. adds legacy in-repo key patterns to `.gitignore`;
6. vendors the tool to `tools/witness/` so clones are self-sufficient;
7. refuses to write its hook anywhere outside the target repository.

Then commit the chain and the vendored tool:

```bash
git add .witness/ tools/ && git commit
```

The first commit in a fresh repo initialises the chain automatically.

---

## Commands

```
witness init                        generate signing keypair (key stored outside the repo)
witness init --force-new-key        start a fresh identity over an orphaned chain
witness init --new-identity         add a second key to an existing chain
witness record --actor A --summary "…" [--files a.ts,b.ts]
witness regress --of <index>        mark an earlier change as regressed
witness verify                      check chain integrity (exit 1 on tamper)
witness report                      write .witness/report.md
witness selftest                    prove tampering is detected
```

`init` **refuses** to mint a new key over an existing signed chain, because that
would silently orphan every signature ever written. If you have lost the key,
it tells you so and names the ways forward (`--new-identity` to add a second
signer, `--force-new-key` to accept the loss, or restore the key directory).

`verify` exits 0 when intact and 1 when tampered, so it drops straight into CI.

`report` writes a Markdown table of the whole chain — index, timestamp, actor,
action, summary, files touched, hash — plus integrity status and the regression
count.

---

## Key custody

**The private key is never in the repository.** It lives at:

```
~/.witness/keys/<keyId>.json      (mode 600)
```

Only the **public** key is committed, in `.witness/pubkey.json`. This is the
property that makes the chain useful: anybody can verify it, and nobody can
forge it.

Consequences worth knowing:

- **Verification never needs the private key.** You can delete your key
  directory and `witness verify` still says `CHAIN INTACT` — and still catches a
  forged entry. This is tested, not asserted (section 12 of the suite).
- **Losing the key is losing the ability to add entries** to that chain, not the
  ability to check it.
- **Committing `.witness/chain.jsonl` and `.witness/pubkey.json` is correct and
  intended.** That is how a clone learns the chain exists. Only key *material*
  is excluded.

---

## Multiple signers

`pubkey.json` is a registry:

```json
{ "keys": [ { "keyId": "89df…", "publicKey": "302a…", "createdAt": "…" },
            { "keyId": "ci-runner", "publicKey": "302a…", "createdAt": "…" } ] }
```

Verification tries **every** key against every entry and reports which signed
what. So a chain can be co-signed by you, a teammate, and CI, and a single
signature failure names the entry rather than condemning the whole file.

The older single-key shape (`{keyId, publicKey}` with no `keys` array) is still
read correctly, so existing chains keep verifying.

To join as a second signer:

```bash
WITNESS_KEY_ID=teammate node witness.mjs init --new-identity
git add .witness/pubkey.json && git commit
```

Commit the updated `pubkey.json` — it is what lets everyone verify the new
entries.

---

## Working in a clone

This is the part that is easy to get silently wrong, so it is worth being
precise about what does and does not survive `git clone`:

| Travels with the clone | Does **not** |
|---|---|
| `.witness/chain.jsonl` | `.git/hooks/` |
| `.witness/pubkey.json` | `.git/config` |
| `tools/witness/` (vendored tool) | your `~/.witness/keys/` |

So a fresh clone has **no hook and no pinned config**. Without a fix, a
contributor's commits would simply go unrecorded — provenance stopping silently
at the fork, which is the exact failure this tool exists to prevent.

The fix, all of which is in place:

1. **The tool is vendored** to `tools/witness/`, so a clone has a working tool
   even with no config. The hook falls back to `node_modules/witness/` and
   `tools/witness/` before the pinned absolute path.
2. **The key id is recovered from the committed `pubkey.json`.** Since neither
   hooks nor config travel, the committed public key is the one thing a clone
   reliably inherits.
3. **`git clone` then `node install-hook.mjs .`** is one command, and the
   installer re-pins both settings.

```bash
git clone <repo> && cd <repo>
node install-hook.mjs .              # reinstall the hook, re-pin, re-vendor
git add .witness/ tools/ && git commit
```

`witness.bin` set but missing is a hard error, not a reason to search elsewhere.
A clone that tries to use a broken configured tool should stop and tell you, not
quietly substitute a different one.

---

## Environment variables

| Variable | Effect |
|---|---|
| `WITNESS_SKIP=1` | skip recording for one commit; prints that it skipped |
| `WITNESS_KEY_DIR` | where private keys live (default `~/.witness/keys`) |
| `WITNESS_KEY_ID` | which key to sign with; how a second signer or a clone adopts an identity |
| `WITNESS_BIN` | override the tool path the hook uses |
| `WITNESS_ACTOR` | override the recorded actor (default `git config user.name`) |

---

## Testing

```bash
node witness.mjs selftest    # 19 checks — the crypto and the two attacks
node test-all.mjs            # 41 checks, 12 sections — the real product
```

`test-all.mjs` is the end-to-end suite. It creates real git repos in a temp
directory, makes real commits through the real installed hook, and then attacks
the chain the way an attacker would — sections 6 and 7 are the two attack models
above, run against a genuine repo. It covers install, recording, real summaries,
the escape hatch, both attacks, recovery, regression tracking, the report,
fail-closed behaviour, and key custody. It asserts on *absence* too: that a
refused commit did not land, and that the private key is not in the repo.

```bash
node test-all.mjs
# 41 passed, 0 failed
```

---

## Files

```
witness.mjs           the CLI — key custody, chain, verify, report, selftest
install-hook.mjs      installs the hook, pins config, vendors the tool
hooks/commit-msg      the git hook itself (POSIX sh, no dependencies)
test-all.mjs          end-to-end suite, 41 checks
package.json          no dependencies; scripts for the commands above
.witness/chain.jsonl  the chain            ← commit this
.witness/pubkey.json  public keys only     ← commit this
.witness/report.md    generated by `witness report`
```

`.witness/keys.json` and `.witness/*.bak` are gitignored — those would be
legacy in-repo key material and must never be committed.

---

## Limitations (read this)

Honest accounting, because a security tool that oversells itself is worse than
none.

1. **A signer can re-sign from scratch.** Delete `chain.jsonl`, rewrite history,
   sign it all again: it verifies. The chain is tamper-**evident**, not
   tamper-**proof**, against someone holding the signing key. Closing this needs
   an external anchor — publishing `chain[N].hash` somewhere append-only and
   independent of the signer (a public timestamp service, a transparency log, a
   notarised digest). Not implemented. It is the single most important thing
   missing.
2. **No enforcement.** `witness verify` records and reports; nothing blocks a
   bad merge. A CI step running `verify` on every PR is the obvious next piece
   and is not written yet.
3. **Local hook, locally skippable.** `WITNESS_SKIP=1`, `--no-verify`, or
   editing `.git/hooks/` all bypass recording. It is loud, not impossible.
4. **A signature proves authorship of a hash, not truth of a claim.** It proves
   *this key* recorded *this text at this time*. It does not prove the code
   works, the change was good, or the summary is accurate.
5. **Clocks are the author's.** Timestamps are the recording machine's clock,
   not a trusted one.
6. **Not published.** No npm package, no signed releases, no portability
   testing beyond the Node version stated above.

---

## License

MIT. See [LICENSE](LICENSE).
