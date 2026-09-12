#!/usr/bin/env python3
"""
watchdog_check.py — the independent watcher.

Runs from this (memory) repository on a cron. Its only job is to make sure a
runner is alive: when the serving node goes silent, it dispatches a fresh node
workflow. It also tidies up stale Tailscale devices so the stable hostname is
never blocked by a ghost of a dead runner, and it verifies the integrity of the
state files against the fleet public key.

It is deliberately dumb, dependency-free and idempotent — it must work even if
the main repository's own automation is broken.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(ROOT, "config", "watchdog.env")
TOKEN = os.environ.get("WORKFLOW_PAT", "")
TS_TOKEN = os.environ.get("TS_API_TOKEN", "")
TAG = os.environ.get("TS_TAG_OVERRIDE", "")
RUN_ID = os.environ.get("GITHUB_RUN_ID", "0")


def cfg() -> dict:
    data = {}
    try:
        with open(CONFIG_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
    except OSError:
        pass
    return data


def log(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} [watchdog] {msg}", flush=True)


def read_json(path: str, default: dict | None = None) -> dict:
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return default or {}


def write_json(path: str, payload: dict) -> None:
    full = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def sign(path: str) -> None:
    key = os.environ.get("FLEET_SIGN_KEY_FILE", "")
    if not key or not os.path.exists(key):
        log(f"no signing key available — {path} left unsigned")
        return
    subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", key, "-n", "fleet-manifest", path],
                   check=False)


def api(path: str, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"https://api.github.com{path}", method=method,
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "memory-watchdog"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read().decode()[:300]}
    except Exception as exc:  # noqa: BLE001
        return 0, {"error": str(exc)}


# --------------------------------------------------------------------------- 
def node_is_alive(c: dict) -> tuple[bool, dict]:
    hb = read_json("state/heartbeat.json")
    age = int(time.time()) - int(hb.get("epoch") or 0)
    stale_after = int(c.get("STALE_MINUTES", "30")) * 60
    alive = age < stale_after and hb.get("status") == "running"
    log(f"heartbeat age={age}s status={hb.get('status')} role={hb.get('role')} "
        f"funnel={(hb.get('funnel') or {}).get('enabled')} -> {'alive' if alive else 'SILENT'}")
    return alive, hb


def running_runs(c: dict) -> int:
    total = 0
    for status in ("in_progress", "queued", "waiting", "requested", "pending"):
        code, data = api(f"/repos/{c.get('MAIN_OWNER')}/{c.get('MAIN_REPO')}/actions/workflows/"
                         f"{c.get('MAIN_WORKFLOW')}/runs?status={status}&per_page=10")
        if code == 200:
            total += len([r for r in data.get("workflow_runs", [])])
    return total


def dispatch_node(c: dict, reason: str) -> bool:
    code, data = api(f"/repos/{c.get('MAIN_OWNER')}/{c.get('MAIN_REPO')}/actions/workflows/"
                     f"{c.get('MAIN_WORKFLOW')}/dispatches", "POST",
                     {"ref": "main", "inputs": {"reason": reason, "supersedes": "",
                                                "successor": "watchdog"}})
    if code in (204, 200):
        log(f"dispatched {c.get('MAIN_WORKFLOW')} ({reason})")
        return True
    log(f"dispatch failed: HTTP {code} {data.get('error','')}")
    return False


def reap_tailscale_devices(c: dict) -> int:
    """delete offline tagged devices older than TTL so the hostname is free"""
    if not TS_TOKEN:
        log("no Tailscale API token — skipping device reaping")
        return 0
    tag = TAG or c.get("TS_TAG", "tag:ci")
    ttl = int(c.get("DEVICE_TTL_MINUTES", "45"))
    req = urllib.request.Request(
        "https://api.tailscale.com/api/v2/tailnet/-/devices",
        headers={"Authorization": f"Bearer {TS_TOKEN}", "User-Agent": "memory-watchdog"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            devices = json.loads(resp.read().decode()).get("devices", [])
    except Exception as exc:  # noqa: BLE001
        log(f"tailscale device listing failed: {exc}")
        return 0

    removed = 0
    now = time.time()
    for dev in devices:
        tags = dev.get("tags") or []
        if tag not in tags:
            continue
        if dev.get("connectedToControl"):
            continue
        seen = dev.get("lastSeen") or ""
        try:
            seen_ts = time.mktime(time.strptime(seen[:19], "%Y-%m-%dT%H:%M:%S"))
            age_min = (now - seen_ts) / 60
        except Exception:  # noqa: BLE001
            age_min = ttl + 1
        if age_min < ttl:
            continue
        dev_id = dev.get("id")
        dreq = urllib.request.Request(
            f"https://api.tailscale.com/api/v2/device/{dev_id}", method="DELETE",
            headers={"Authorization": f"Bearer {TS_TOKEN}", "User-Agent": "memory-watchdog"})
        try:
            with urllib.request.urlopen(dreq, timeout=20) as resp:
                if resp.status in (200, 204):
                    removed += 1
                    log(f"removed stale device {dev.get('name')} (offline {int(age_min)} min)")
        except Exception as exc:  # noqa: BLE001
            log(f"failed to remove {dev.get('name')}: {exc}")
    return removed


def verify_integrity(c: dict) -> dict:
    if c.get("INTEGRITY_CHECK", "true") != "true":
        return {"skipped": True}
    signers = os.path.join(ROOT, "keys", "allowed_signers")
    result = {"checked": [], "failures": []}
    if not os.path.exists(signers):
        result["failures"].append("keys/allowed_signers missing")
        return result
    for rel in ("state/lease.json", "state/heartbeat.json", "manifest/blobs.json"):
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            continue
        proc = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-q", "-f", signers, "-I", "fleet",
             "-n", "fleet-manifest", "-s", path + ".sig"],
            stdin=open(path, "rb"), capture_output=True, text=True)
        if proc.returncode == 0:
            result["checked"].append(rel)
        else:
            result["failures"].append(rel)
            log(f"INTEGRITY FAILURE: {rel} signature invalid")
    return result


def keepalive_commit(c: dict) -> bool:
    """daily commit to the main repo: keeps its scheduled workflows enabled"""
    if c.get("KEEPALIVE_COMMIT", "true") != "true":
        return False
    marker = os.path.join(ROOT, "state", "keepalive.last")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        with open(marker, encoding="utf-8") as fh:
            if fh.read().strip() == today:
                return False
    except OSError:
        pass
    path = "activity/chain-keepalive.txt"
    url = f"/repos/{c.get('MAIN_OWNER')}/{c.get('MAIN_REPO')}/contents/{path}"
    code, data = api(url)
    sha = data.get("sha") if code == 200 else None
    body = {"message": f"chain keepalive {today} (automated, keeps scheduled workflows enabled)",
            "content": base64.b64encode(f"chain alive {today}\n".encode()).decode(),
            "branch": "main"}
    if sha:
        body["sha"] = sha
    code, data = api(url, "PUT", body)
    if code in (200, 201):
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(today + "\n")
        log("keepalive commit pushed to the main repository")
        return True
    log(f"keepalive commit failed: HTTP {code} {data.get('error','')}")
    return False


def main() -> int:
    c = cfg()
    log(f"watchdog run {RUN_ID}")
    alive, hb = node_is_alive(c)
    integrity = verify_integrity(c)
    removed = reap_tailscale_devices(c)

    dispatched = False
    active = 0
    if not alive:
        active = running_runs(c)
        log(f"no live node; node workflows currently active: {active}")
        if active == 0:
            dispatched = dispatch_node(c, "watchdog-recovery")
        else:
            log("a node workflow is already starting — not dispatching another")
    keepalive_commit(c)

    state = {
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "watchdog_run": RUN_ID,
        "node_alive": alive,
        "heartbeat_age_seconds": int(time.time()) - int(hb.get("epoch") or 0),
        "active_node_runs": active,
        "dispatched": dispatched,
        "stale_devices_removed": removed,
        "integrity": integrity,
    }
    write_json("state/watchdog.json", state)
    sign(os.path.join(ROOT, "state", "watchdog.json"))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write("## memory watchdog\n\n")
            fh.write(f"- node alive: **{alive}** (heartbeat age {state['heartbeat_age_seconds']}s)\n")
            fh.write(f"- dispatched replacement: **{dispatched}** (active runs seen: {active})\n")
            fh.write(f"- stale tailscale devices removed: {removed}\n")
            fh.write(f"- integrity: {len(integrity.get('checked', []))} ok, "
                     f"{len(integrity.get('failures', []))} failed\n")
    log(f"done: alive={alive} dispatched={dispatched} removed={removed} "
        f"integrity_failures={len(integrity.get('failures', []))}")
    # exit 1 when the chain looks broken and we could not fix it — that turns the
    # workflow red and GitHub notifies you
    if not alive and not dispatched and active == 0:
        return 1
    if integrity.get("failures"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
