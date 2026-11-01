"""Bind a `receipt_uri` to a `SecurityEvent` via an independently verifiable
anchor — the operator-side flow described by @vgudur-dev in
OWASP/www-project-agent-memory-guard#43 (2026-11-01):

    "write() accepts receipt_uri on every SecurityEvent so it can point at
    an external receipt. The operator computes the action_ref, anchors it
    wherever it wants, and passes the link — that's how you correlate the
    guard's decision with the anchor. The core stays offline, no external
    calls; anchoring is strictly outside the core."

This example plays the operator side of that contract end to end:

1. Compute `action_ref` — a deterministic, content-addressed identifier for
   the write — using the reference derivation from argentum-core's
   docs/spec/action-ref.md: SHA-256 over the RFC 8785 JCS canonical form of
   four fields (agent_id, action_type, scope, timestamp). That spec already
   documents `action_type="memory_write"` / `scope=<memory key>` as its own
   worked case for this exact gap class — see "Memory provenance
   attestation (OWASP ASI06)" in action-ref.md. The derivation is inlined
   below rather than imported: argentum-core is a reference, not a
   dependency AMG should take on. Any implementation producing the same
   four-field JCS+SHA-256 digest interoperates with any other.
2. Anchor it on Base mainnet via AnchorRegistry
   (0x49fEcA52bC634a9Ab773226D16619deC547794aa) — a permissionless
   `anchor(bytes32)` call any EOA can make, no account or API key needed.
   Emits `Anchored(bytes32 ref, address anchoredBy, uint256 timestamp)`.
   Anyone can verify independently via `eth_getTransactionReceipt` against
   any Base RPC node — no trust in this script, argentum-core, or any
   particular RPC endpoint required.
3. Pass the resulting receipt URI into `guard.write(..., receipt_uri=...)`.
   AMG's core never makes the network call in step 2 — this script does,
   entirely outside the guard, exactly as vgudur-dev described.

This script does NOT anchor automatically — anchoring spends real gas, and
nothing should spend a reader's funds just by running an example. It prints
the exact command to anchor yourself; pass the resulting tx hash back in to
see the full receipt_uri binding:

    pip install -e .
    python examples/action_ref_receipt_binding.py                # steps 1 + the anchor command
    python examples/action_ref_receipt_binding.py <anchor_tx_hash>  # + steps 2-3, verified on-chain

AMG does not require argentum-core or this specific anchor backend. Any
scheme that produces a dereferenceable receipt_uri fits the same contract;
this example exists to make that contract's shape concrete, not to suggest
argentum-core is AMG's required anchor backend.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import sys
import urllib.request

from agent_memory_guard import MemoryGuard, SourceClass

REGISTRY = "0x49fEcA52bC634a9Ab773226D16619deC547794aa"
RPC = "https://mainnet.base.org"
ANCHORED_TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"


# --- action_ref: reference derivation, argentum-core docs/spec/action-ref.md ---

def _jcs_encode(fields: dict[str, str]) -> bytes:
    """RFC 8785 JCS for a flat dict of ASCII string values: sorted keys, no
    whitespace, UTF-8. (The four keys this profile uses are ASCII-only, so
    code-point sort and RFC 8785's UTF-16-code-unit sort coincide here.)
    """
    return json.dumps(dict(sorted(fields.items())), separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_action_ref(agent_id: str, action_type: str, scope: str, timestamp: str) -> str:
    payload = {"agent_id": agent_id, "action_type": action_type, "scope": scope, "timestamp": timestamp}
    return hashlib.sha256(_jcs_encode(payload)).hexdigest()


def format_timestamp(dt: datetime.datetime) -> str:
    """RFC 3339 UTC, 3-digit ms, mandatory 'Z' — the one byte sequence per
    instant action-ref.md's Domain requires."""
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


# --- verify: confirm an anchor tx directly against a public Base RPC node ---

def verify_anchor(action_ref: str, tx_hash: str) -> str:
    """Fetches the tx receipt, confirms an Anchored(action_ref, ...) log from
    REGISTRY, and returns a dereferenceable receipt_uri. Raises on mismatch
    or if the tx reverted/isn't found -- this never trusts a claimed receipt_uri,
    it recomputes the check from the chain directly."""
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx_hash]}
    ).encode()
    req = urllib.request.Request(
        RPC,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "agent-memory-guard-example/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        receipt = json.loads(resp.read())["result"]
    assert receipt is not None, "tx not found on mainnet.base.org"
    assert receipt["status"] == "0x1", "tx reverted"
    for log in receipt["logs"]:
        if log["address"].lower() == REGISTRY.lower() and log["topics"][0].lower() == ANCHORED_TOPIC0:
            ref_onchain = log["topics"][1][2:]
            assert ref_onchain.lower() == action_ref.lower(), "on-chain ref != action_ref"
            return f"https://basescan.org/tx/{tx_hash}"
    raise AssertionError("no Anchored log for this action_ref at this tx")


def main() -> None:
    guard = MemoryGuard()

    agent_id = "amg-example-agent-01"
    key = "tool.search.42"
    action_type = "memory_write"
    scope = f"mycelium:memory:{key}"  # action-ref.md's own OWASP ASI06 case
    timestamp = format_timestamp(datetime.datetime.now(datetime.timezone.utc))

    action_ref = compute_action_ref(agent_id, action_type, scope, timestamp)
    print("action_ref:", action_ref)
    print("  independently recomputable by anyone holding agent_id/action_type/scope/timestamp —")
    print("  see docs/spec/action-ref.md in https://github.com/giskard09/argentum-core\n")

    print("to anchor it on Base mainnet (any EOA, no account or API key):")
    print(f'  cast send {REGISTRY} "anchor(bytes32)" 0x{action_ref} \\')
    print('    --rpc-url https://mainnet.base.org --private-key $PRIVATE_KEY\n')

    tx_hash = sys.argv[1] if len(sys.argv) > 1 else None
    if not tx_hash:
        print("(no anchor tx given — pass it as argv[1] to see the receipt_uri binding)")
        return

    receipt_uri = verify_anchor(action_ref, tx_hash)
    print("anchored and verified on-chain:", receipt_uri)

    decision = guard.write(
        key,
        "Acme Q3 revenue was $42M",
        source_class=SourceClass.EXTERNAL_TOOL,
        receipt_uri=receipt_uri,
    )
    event = guard.events[-1]
    print("\nguard decision:", decision.value)
    print("SecurityEvent.receipt_uri:", event.receipt_uri)
    assert event.receipt_uri == receipt_uri, "receipt_uri did not round-trip onto the SecurityEvent"
    print("\nOK — SecurityEvent.receipt_uri correlates to an independently verifiable anchor.")


if __name__ == "__main__":
    main()
