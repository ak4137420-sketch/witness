#!/bin/sh
# ci-verify.sh - fail a build when the witness chain is broken or has lost entries.
#
# Runs `witness verify` AND closes the hole that verify alone cannot see.
#
# `witness verify` is integrity-checking, not completeness-checking. Given a
# chain with entries 0-6 and an attacker who deletes entries 4-6, it reports
# "CHAIN INTACT" and exits 0 -- because 0-3 are still a perfectly valid prefix.
# A CI job that only runs verify is a green check on a gutted chain. Both of
# these are real, both exit 0 today:
#
#     chain.jsonl deleted      -> "0 entries checked - CHAIN INTACT", exit 0
#     chain.jsonl truncated    -> "4 entries checked - CHAIN INTACT", exit 0
#
# The chain is append-only, so losing entries from the END is itself evidence of
# tampering. Nothing inside the chain can detect that -- the file cannot know how
# many entries it was supposed to have. The expected count has to come from
# somewhere the attacker did not edit, so it comes from the BASE BRANCH, read
# out of git history. A pull request can add entries; it can never lower the
# count the gate compares against.
#
# Usage (GitHub Actions, in a checkout with full history):
#     sh ci-verify.sh origin/main
#
# Any argument is accepted as the trusted ref. With no argument it falls back to
# the upstream tracking branch, then to main, then to master.

set -e

here=$(cd "$(dirname "$0")" && pwd)
root=$(git rev-parse --show-toplevel)
cd "$root"

# Prefer the vendored copy, then this checkout, so the gate tests the tool that
# actually ships rather than whatever happens to be on the machine.
if [ -f "$root/tools/witness/witness.mjs" ]; then
  tool="$root/tools/witness/witness.mjs"
elif [ -f "$here/witness.mjs" ]; then
  tool="$here/witness.mjs"
else
  echo "ci-verify: cannot find witness.mjs" >&2
  exit 1
fi

fail() { echo "ci-verify: $*" >&2; exit 1; }

# ---- 0. does this repo use witness at all? -----------------------------
# Not every repo that vendors this tool records a chain -- a project can depend
# on witness without adopting it. A gate that hard-failed on a missing chain
# would break CI for every such repo on the first run, so the base branch
# decides. If the base branch never had a chain, this pull request is not
# removing one; there is nothing to protect yet.
base_ref_for_absence=$1
if [ ! -f .witness/chain.jsonl ]; then
  # Distinguish "this repo never used witness" from "someone deleted the chain".
  # The public key is the tell: it survives a deleted chain, because an attacker
  # deleting the evidence has no reason to delete the key that made forging it
  # hard. Its presence means a chain is expected here.
  if [ -f .witness/pubkey.json ]; then
    if [ -n "$base_ref_for_absence" ] \
       && MSYS_NO_PATHCONV=1 git cat-file -e "$base_ref_for_absence:.witness/chain.jsonl" 2>/dev/null; then
      fail "no .witness/chain.jsonl in this checkout, but $base_ref_for_absence has one - the chain was deleted in this PR"
    fi
    fail ".witness/pubkey.json is present but the chain is gone - the chain was deleted"
  fi
  echo "ci-verify: this repo has no witness chain - nothing to verify, skipping"
  exit 0
fi

# From here on a missing chain IS a failure: the evidence that a chain should
# exist is either the chain itself, the public key that goes with it, or the
# base branch.
[ -f .witness/chain.jsonl ] || fail "no .witness/chain.jsonl in this checkout, and no chain on the base branch either - cannot verify"

actual=$(grep -c '[^[:space:]]' .witness/chain.jsonl || true)
[ "$actual" -gt 0 ] || fail ".witness/chain.jsonl is empty"

# ---- 2. the trusted ref, for the expected count ------------------------
ref=${1:-}
if [ -z "$ref" ]; then
  ref=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)
fi
[ -n "$ref" ] || ref=main
git rev-parse --verify "$ref" >/dev/null 2>&1 || ref=master
git rev-parse --verify "$ref" >/dev/null 2>&1 \
  || fail "no trusted ref to compare against (tried '$1', upstream, main, master). Pass one explicitly: sh ci-verify.sh origin/main"

# ---- 3. the PR may not have lost entries --------------------------------
# Read the base branch's chain from git history, NOT from the working tree: a
# pull request controls the working tree, but not the base branch's commits.
# MSYS_NO_PATHCONV=1 matters: Git Bash rewrites the colon in <ref>:<path> into a
# backslash on Windows ("origin/master:.witness/..."), which turns this into a
# fatal "not a valid object name" and silently reads as a base branch with no
# chain -- the entry-count check would be skipped on every Windows run.
MSYS_NO_PATHCONV=1
export MSYS_NO_PATHCONV
base_count=$(git show "$ref:.witness/chain.jsonl" 2>/dev/null | grep -c '[^[:space:]]' || true)

if [ "$base_count" -gt 0 ]; then
  if [ "$actual" -lt "$base_count" ]; then
    echo "ci-verify: TAMPERING - the chain lost entries." >&2
    echo "  $ref has $base_count entries, this branch has $actual." >&2
    echo "  The chain is append-only; entries cannot be removed. Someone deleted" >&2
    echo "  history, or the branch was rewound. Both need investigating." >&2
    exit 1
  fi
  echo "ci-verify: $actual entries (base $ref has $base_count) - no entries lost"
else
  # No chain on the base branch: first run, or a repo that has only just adopted
  # witness. There is nothing to lose yet, so this is not a failure.
  echo "ci-verify: $ref has no chain yet - nothing to compare, skipping the entry-count check"
fi

# ---- 4. the actual cryptographic check ----------------------------------
# Deliberately LAST, so that an entry-count failure is reported on its own terms
# rather than buried in a pile of signature errors.
if node "$tool" verify; then
  echo "ci-verify: PASS"
else
  echo "ci-verify: FAIL - the chain does not verify. Do not merge." >&2
  exit 1
fi
