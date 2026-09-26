# Change provenance report

- Generated: 2026-09-26T15:52:02Z
- Signing key: `89df454c1303f2b7` (public keys in `.witness/pubkey.json`; private keys held outside the repo)
- Entries: 11
- Integrity: **VERIFIED** (Ed25519 chain, 11 entries checked)
- Regressions recorded: 1
- Distinct files touched: 17

## Chain

| # | Timestamp | Actor | Action | Summary | Files | Hash |
|---|---|---|---|---|---|---|
| 0 | 2026-09-26T11:37:07Z | claude-opus | commit | scaffold witness CLI | 2 | c45835db4753 |
| 1 | 2026-09-26T11:37:08Z | claude-opus | commit | add regression tracking | 1 | 2be76f4953d0 |
| 2 | 2026-09-26T11:37:08Z | claude-opus | commit | fix selftest to cover rehashed-edit attack | 1 | 89fd11eeed8b |
| 3 | 2026-09-26T11:37:08Z | witness | regression | regression of #1 | - | c977e7366437 |
| 4 | 2026-09-26T13:12:25Z | ak4137420-sketch | commit | witness: tamper-evident provenance for agent changes | 14 | 1edd03df1af7 |
| 5 | 2026-09-26T13:22:42Z | ak4137420-sketch | commit | chain: record the release commit itself | 2 | 30c614248a1d |
| 6 | 2026-09-26T13:24:10Z | ak4137420-sketch | commit | docs: explain why the chain always lags one entry behind | 3 | 1a108fd4f17c |
| 7 | 2026-09-26T13:49:43Z | ak4137420-sketch | commit | ci: gate every pull request on chain integrity | 5 | f867efa851ce |
| 8 | 2026-09-26T13:52:01Z | ak4137420-sketch | commit | ci: name the workflow main.yml | 1 | 0bd75fd59f81 |
| 9 | 2026-09-26T13:52:23Z | ak4137420-sketch | commit | merge: the workflow added from the GitHub UI | 1 | 764275613e58 |
| 10 | 2026-09-26T13:53:10Z | ak4137420-sketch | commit | chain: record the merge and the CI commits | 1 | b9e9f6c7fccc |

