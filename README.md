# mrphon3shop-data — the encrypted memory repository

This repository is the **persistent disk** of a system that runs on ephemeral
GitHub-hosted runners. The runners die every few hours; everything that must
survive lives here.

It is a **public** repository on purpose (no GitHub Actions minutes are spent on
it), which is why **nothing readable is ever stored in it**:

| path | contents | protection |
|---|---|---|
| `blobs/*.tar.zst.age` | application data, application config, package inventory, operator intent, Tailscale identity | **age** (X25519) — unreadable without the private identity, which exists only as a GitHub secret |
| `manifest/blobs.json` | hash index of every blob (anti-tamper + anti-rollback) | signed with the fleet key |
| `state/lease.json` | which run currently owns the node (single writer) | signed |
| `state/heartbeat.json` | liveness beacon of the serving node | signed |
| `state/handoff.json` | handover/standby signalling between two runners | signed |
| `state/nodes.jsonl` | append-only machine log of boots | — |
| `keys/allowed_signers` | public key used to verify the signatures above | public by design |
| `config/watchdog.env` | tunables for the watchdog | public |
| `scripts/` | the watchdog + maintenance tooling | public |

## Why a public repository is safe here

* every payload is encrypted with **age** before it is committed; the private
  identity (`AGE_IDENTITY`) is a GitHub Actions secret of this repository and of
  `mrphon3shop.com`
* the plaintext state files are **signed** (`ssh-keygen -Y sign`); the node
  refuses to act on an unsigned or invalid lease
* an attacker with write access to this repository can, at worst, make a node
  think it owns the lease (a denial of service) — they cannot decrypt data and
  cannot make a node install a package, because the desired-state delta is
  inside an encrypted blob and is restricted to `apt`/`bin` kinds by the node
  before anything is executed

## Watchdog

`.github/workflows/watchdog.yml` runs every 10 minutes. If the serving node has
been silent for `STALE_MINUTES`, it dispatches a fresh node workflow, and it
removes offline Tailscale devices so the stable hostname is never blocked by a
ghost of a dead runner. It is independent of the node repository by design.

## Manual tools

Actions → **memory-tools**:

* `verify` — check every signature and blob hash, print the inventory
* `restore` — decrypt the latest snapshot into a downloadable artifact
* `rotate` — re-encrypt everything for a new age recipient

## Never commit

* `AGE_IDENTITY`, `FLEET_SIGN_KEY`, `WORKFLOW_PAT`, `TS_API_KEY` — secrets
* a decrypted blob, a `.age` private key, or a copy of `authorized_keys` from a
  running node
