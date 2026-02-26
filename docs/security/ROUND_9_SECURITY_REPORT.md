# PyHall v0.1 — Round 9 Security Report

**Date:** 2026-02-26
**Scope:** Attestation system — 7 targeted attack scenarios (R1–R7)
**Analyst:** Claude (FΔFΌ★LΔB primary development agent)
**Codebase:** `/mnt/fafolab/dev/pyhall/git`
**SDKs under test:** Python (`sdk/python/pyhall/`), TypeScript (`sdk/typescript/src/`), Go (`sdk/go/wcp/`)
**Context:** Final pre-release security pass (Rounds 1–8 previously completed)

---

## Attestation System Overview

PyHall's worker attestation system (WCP §5.10) operates as follows:

1. At enrollment time, each worker species registers a SHA-256 hash of its source code via `registry.register_attestation()` or via the `attestation.code_hash` field in the enrollment JSON record.
2. At dispatch time, when `HallConfig.require_worker_attestation=True`, the router calls `get_current_worker_hash()` (which reads the file from disk, bypassing Python's import cache) and compares it to the registered hash.
3. Any mismatch, missing hash, or malformed hash produces a deny decision. The router never silently permits dispatch when attestation is required.

The parity checker (`tools/qc/sdk_parity.py`) verifies that all three SDKs implement the same set of five attestation deny codes and that CV-013 conformance vectors are present in all three test suites.

---

## R1: Hash Substitution in Catalog

### Attack Description

An attacker with write access to the registry storage substitutes a known-good worker's registered hash with the SHA-256 hash of malicious replacement code. The goal is to pre-register the malicious hash so that when the malicious file is deployed, the attestation check passes.

This is a supply-chain attack: the attacker controls the reference value rather than trying to bypass the comparison.

### Defense Mechanism

**catalog_validator.py:** `tools/qc/catalog_validator.py` validates catalog entity IDs for format and version-suffix compliance (WCP §3.2/§3.4), but the catalog (`catalog.json`) is a taxonomy document — it does not store registered worker hashes. Hashes are stored in the Registry (`registry._attestation_hashes`) populated at enrollment time from worker JSON records or via `register_attestation()`.

**Registry enrollment validation** (`sdk/python/pyhall/registry.py`, lines 164–174): At enrollment, the hash format is validated against `_VALID_HASH_RE = re.compile(r'^[0-9a-f]{64}$')`. An invalid-format hash is rejected with a warning and not stored. A validly-formatted malicious hash (64 lowercase hex chars) would be accepted — format validation does not verify the hash's origin.

**Router enforcement** (`sdk/python/pyhall/router.py`, lines 632–645): The router validates the registered hash format again at dispatch time using `_VALID_HASH = re.compile(r'^[0-9a-f]{64}$')`. If the registered hash is malformed, `DENY_WORKER_ATTESTATION_INVALID_HASH` fires.

**Key constraint:** The attestation system is a content-integrity check, not a chain-of-custody check. If an attacker can write to the registry storage that backs `_attestation_hashes`, they can substitute a hash and the system will accept the corresponding malicious file. The defense is **access control on the registry store** — WCP delegates this to the Hall operator and does not implement it internally (WCP's security model is explicitly perimeter-based, documented in `sdk/go/wcp/router.go` lines 319–323: "WCP's security model is perimeter-based: it defends against unauthorized dispatch, not against a compromised Hall operator").

**Build pipeline:** The `catalog_validator.py` at `tools/qc/catalog_validator.py` does not validate hashes because hashes are not stored in the catalog. There is no build-time hash registry integrity check in the codebase — this is by design; the Hall operator is expected to control registry access.

**Go parity** (`sdk/go/wcp/router.go`, line 626): `validHashRe.MatchString(registeredHash)` — same 64-char hex validation.

**TypeScript parity** (`sdk/typescript/src/router.ts`, line 893): `const VALID_HASH = /^[0-9a-f]{64}$/;` — same 64-char hex validation.

### Severity if Defense Were Absent

**Critical** — An attacker who can register arbitrary hashes can whitelist any malicious worker code.

### Status

**CONDITIONAL MITIGATED** — The router correctly enforces hash format and comparison. The catalog_validator does not check registry hashes (not its scope). The practical security of R1 depends entirely on access control to the registry store, which is a Hall operator responsibility explicitly documented in the WCP security model. No code-level vulnerability in PyHall itself; the architectural dependency on operator-controlled registry integrity is by design and documented.

---

## R2: Worker Source Tampering (Router Bypass)

### Attack Description

An attacker modifies a worker species' source file on disk after its hash was registered. On the next routing request, the modified (potentially malicious) worker is dispatched instead of the known-good version.

### Defense Mechanism

**registry.compute_current_hash()** (`sdk/python/pyhall/registry.py`, lines 286–301): Every call reads the worker file directly from disk using `path.read_bytes()`, bypassing Python's module import cache. This means the hash reflects the current on-disk state at the moment of each dispatch check — there is no stale-cache window.

**Router comparison** (`sdk/python/pyhall/router.py`, lines 662–681): At Step 6.5, the router calls `get_current_worker_hash(selected)` and compares the result to `registered_hash`. An exact full-string mismatch (`current_hash != registered_hash`) produces `DENY_WORKER_TAMPERED` with `worker_attestation_valid=False`. The hash values themselves are not returned to the caller (F4 security, router.py line 664: "F4: Do NOT return hash values to caller — log internally only").

**All three SDKs verified:**
- Python: `sdk/python/pyhall/router.py` line 662: `if current_hash != registered_hash:`
- TypeScript: `sdk/typescript/src/router.ts` line 971: `if (currentHash !== registeredHash)`
- Go: `sdk/go/wcp/router.go` line 701: `if currentHash != registeredHash`

The parity checker (`tools/qc/sdk_parity.py`, lines 14–46) confirms all three SDKs contain `DENY_WORKER_TAMPERED`.

**Telemetry:** `DENY_WORKER_TAMPERED` emits `evt.os.task.denied` with deny_code, ensuring the tampering event is forensically recorded.

### Severity if Defense Were Absent

**Critical** — Without on-dispatch hash verification, any post-enrollment source modification goes undetected. A compromised worker executes with full Hall authorization.

### Status

**MITIGATED** — `compute_current_hash()` reads from disk on every call. The router enforces the comparison before dispatch. All three SDKs implement the check identically. The parity checker confirms cross-SDK consistency.

---

## R3: Attestation Field Omission

### Attack Description

An attacker (or a misconfigured client) sends a routing request that attempts to influence the attestation outcome by either:
- Supplying `worker_attestation_checked: false` or `worker_attestation_valid: true` in the request payload to suggest attestation was already performed, or
- Omitting attestation-related fields entirely to trigger a fallback that skips the check.

### Defense Mechanism

**RouteInput does not accept attestation fields** (`sdk/python/pyhall/models.py`, lines 30–100): `RouteInput` has no `worker_attestation_checked` or `worker_attestation_valid` fields. These fields exist only on `RouteDecision` (the output). A caller cannot inject attestation state through the input envelope. Pydantic's `extra='forbid'` behavior applies — extra fields raise a validation error at construction time.

**RouteDecision fields are router-set** (`sdk/python/pyhall/models.py`, lines 292–298): `worker_attestation_checked` and `worker_attestation_valid` are output-only fields on `RouteDecision`. They are set exclusively by the router at lines 852–853 (`router.py`):
```python
worker_attestation_checked=attestation_checked,
worker_attestation_valid=attestation_valid,
```

**Router controls the flag** (`sdk/python/pyhall/router.py`, lines 583–590): `worker_attestation_checked` starts as `False` (line 585) and is set to `True` only when the attestation block actually executes. A request cannot force this flag to `True` without the attestation block running.

**Go parity** (`sdk/go/wcp/router.go`, lines 355–356): `workerAttestationChecked := false` initialized at the top of `MakeDecision`, set to `true` only inside the attestation block at line 550.

**TypeScript parity** (`sdk/typescript/src/router.ts`, line 896): `workerAttestationChecked = true` is set only inside the attestation conditional.

**Deny codes for missing/misconfigured callables:** If attestation is required but callables are missing, `DENY_ATTESTATION_UNCONFIGURED` fires (Python router.py line 596, TS router.ts line 903, Go router.go line 572). The router does not fall through to dispatch.

### Severity if Defense Were Absent

**Critical** — If a caller could assert `worker_attestation_checked: true` through the input, the router could be tricked into skipping the actual check while reporting it as verified.

### Status

**MITIGATED** — Attestation state fields exist only on the output model (`RouteDecision`), not on `RouteInput`. The router exclusively controls these flags. No input-side injection path exists. All three SDKs confirmed.

---

## R4: Hash Collision / Partial Hash Attack

### Attack Description

An attacker attempts to exploit a prefix or substring match: either by registering a hash that matches only the first N characters of the legitimate hash, or by submitting a worker whose partial hash matches via a loose comparison (`startswith`, `in`, or non-exact equality).

### Defense Mechanism

**Full-string equality comparison in all three SDKs:**

- Python (`sdk/python/pyhall/router.py` line 662): `if current_hash != registered_hash:` — Python `!=` on strings requires byte-for-byte equality of the entire string.
- TypeScript (`sdk/typescript/src/router.ts` line 971): `if (currentHash !== registeredHash)` — JavaScript strict inequality `!==` is full-string.
- Go (`sdk/go/wcp/router.go` line 701): `if currentHash != registeredHash` — Go string comparison is exact.

**Hash format validation enforces 64-char length** (`sdk/python/pyhall/registry.py` line 52; `router.py` line 587; `router.go` line 12; `router.ts` line 893): The regex `^[0-9a-f]{64}$` anchors both ends and specifies exactly 64 characters. A 32-char or 48-char partial hash cannot match the format and is rejected by `DENY_WORKER_ATTESTATION_INVALID_HASH` before the comparison is reached.

**Double validation:** The format regex is applied to both the registered hash (at enrollment and at dispatch) and the current hash (at dispatch). A partial hash cannot pass validation on either side of the comparison.

**No timing side-channel noted:** Python, TypeScript, and Go all use native string equality for the comparison. Python's `!=` and Go's `!=` on strings are not constant-time. For a local attestation check (both values derived from SHA-256 of on-disk files), this is not a meaningful attack surface — an attacker would need to control execution timing of the router process itself.

### Severity if Defense Were Absent

**High** — A prefix-match vulnerability would allow an attacker to find a file whose 8-character hash prefix matches the registered hash's prefix, significantly reducing the preimage search space.

### Status

**MITIGATED** — The `^[0-9a-f]{64}$` regex enforces exact 64-character lowercase hex format on both sides of the comparison before the equality check. Full-string equality is used in all three SDKs. No partial match or substring comparison exists in the codebase.

---

## R5: Unconfigured Attestation Fallback

### Attack Description

A Hall operator deploys the system with `HallConfig.require_worker_attestation=True` but forgets to wire in the hash callables (`registry_get_worker_hash` and `get_current_worker_hash`). The expected behavior is a hard deny; the attack scenario is that the router silently falls through to dispatch without actually checking hashes.

### Defense Mechanism

**Python** (`sdk/python/pyhall/router.py`, lines 592–604): When attestation is required but either callable is `None`, the router immediately returns `DENY_ATTESTATION_UNCONFIGURED` before any hash lookup occurs. The message explicitly identifies which callables are missing.

**TypeScript** (`sdk/typescript/src/router.ts`, lines 898–909): Same pattern: `if (!registryGetWorkerHash || !registryGetCurrentWorkerHash)` returns `DENY_ATTESTATION_UNCONFIGURED`.

**Go** (`sdk/go/wcp/router.go`, lines 553–585): `if opts.GetWorkerHash == nil || opts.GetCurrentWorkerHash == nil` returns `DENY_ATTESTATION_UNCONFIGURED`.

**F2 annotation** (Python router.py line 591): "F2: When attestation is required, missing callables are a deny, not a skip." — This was an explicit prior-round security fix (R2 in earlier rounds), confirming the pattern was added intentionally.

**No silent fallback:** None of the three SDKs contain a code path where `require_worker_attestation=True` combined with nil/None callables allows dispatch. The deny is unconditional.

**Parity checker** (`tools/qc/sdk_parity.py`, lines 33–46): Confirms `DENY_ATTESTATION_UNCONFIGURED` exists in all three SDK router files.

### Severity if Defense Were Absent

**Critical** — A silent fallback when callables are missing would nullify the entire attestation system for any deployment that omits the callback wiring. This is the most common misconfiguration scenario.

### Status

**MITIGATED** — All three SDKs unconditionally deny with `DENY_ATTESTATION_UNCONFIGURED` when `require_worker_attestation=True` but callables are not provided. The F2 annotation confirms this was an explicit security design decision.

---

## R6: Race Condition Between Hash Registration and Dispatch (TOCTOU)

### Attack Description

A Time-of-Check/Time-of-Use (TOCTOU) attack: the attacker replaces a worker's source file between the moment the registration hash is computed and the moment the dispatch-time hash is computed. If the window is large enough, the attacker could:

1. Allow the registration scan to capture the known-good file hash.
2. Replace the file with malicious code.
3. Have the malicious code execute before the dispatch-time check reads the file.

Alternatively: replace the file with malicious code, wait for a dispatch, and then restore the original file before the dispatch-time check reads it (swap attack).

### Defense Mechanism

**Registration window:** `registry.register_attestation()` (`sdk/python/pyhall/registry.py`, lines 240–273) hashes the file at the moment of the call and stores the result. This is typically called at Hall startup. The window between file deployment and `register_attestation()` is an operator concern.

**Dispatch-time read** (`sdk/python/pyhall/registry.py`, lines 286–301): `compute_current_hash()` calls `path.read_bytes()` on every invocation, bypassing Python's import cache. There is no caching of the current hash — every dispatch reads the file fresh from disk.

**TOCTOU window analysis:** The window between `path.read_bytes()` in `compute_current_hash()` and the actual worker execution exists at the framework level. PyHall's role ends at the routing decision — it returns a `RouteDecision`, it does not itself execute the worker. The Hall operator is responsible for executing the worker with the same file that was just hashed. PyHall provides no atomicity guarantee between the hash check and execution — this is a known and documented architectural constraint (WCP is a dispatch protocol, not a execution sandbox).

**Practical constraints on swap attack:** To execute the swap attack successfully, the attacker must:
- Have write access to the worker source file (itself a significant privilege).
- Coordinate the file swap within the latency window of a single `path.read_bytes()` call on Linux (typically sub-millisecond for a file in page cache).
- Execute before the Hall operator's code runs the worker.

The sub-millisecond read window makes this practically difficult but not impossible under adversarial conditions (e.g., if the attacker controls the filesystem or can trigger disk I/O delays).

**No mitigations for the execution gap in the current codebase:** PyHall does not lock the worker file during dispatch, does not use `O_NOFOLLOW` or an fd-based hash (hash-then-open-same-fd), and does not pin an immutable snapshot. These would require operating-system-level primitives outside the scope of a pure Python library.

**Warning telemetry for unattested prod:** (`sdk/python/pyhall/router.py`, lines 782–790, F24): When attestation was not checked and env is prod/edge, `evt.os.worker.attestation_skipped` is emitted. This is advisory only.

### Severity if Defense Were Absent

**Medium** — The TOCTOU window is narrow (sub-millisecond) and requires the attacker to already have write access to worker files. However, if exploited on a high-throughput system with many rapid dispatches, the probability of a successful swap rises.

### Status

**PARTIALLY MITIGATED** — `compute_current_hash()` reads from disk on every call with no caching, which eliminates the stale-cache attack vector. However, a true TOCTOU window remains between the hash comparison and the Hall operator's execution of the worker. This is an inherent architectural gap in a library-based (non-sandbox) dispatch model. PyHall cannot close this window without OS-level primitives (file locking, immutable file handles) that are outside its scope. The gap is documented in WCP's security model (perimeter-based defense). **Recommendation:** Hall operators should deploy workers as immutable container images and use container image digest verification as a complementary control.

---

## R7: Policy Gate Bypass via Capability ID Manipulation

### Attack Description

An attacker submits a capability ID that either:
- Does not exist in the catalog or routing rules (unknown ID), hoping for a permissive default.
- Uses a versioned ID (e.g., `cap.doc.summarize.v1`) to route around rules that match on the base ID.
- Uses a malformed or control-character-injected ID to break routing logic.

### Defense Mechanism

**Fail-closed for unknown capabilities:**

Python (`sdk/python/pyhall/router.py`, lines 350–357): `route_first_match(rules, inp.model_dump())` returns `None` if no rule matches. This immediately returns `DENY_NO_MATCHING_RULE` — unknown capability IDs are never dispatched.

Go (`sdk/go/wcp/router.go`, lines 388–399): `registry.WorkersForCapability(input.CapabilityID)` returns an empty slice for unknown IDs, producing `NO_WORKER_FOR_CAPABILITY`.

TypeScript: same pattern in `routeFirstMatch`.

**Catalog validator rejects version suffixes** (`tools/qc/catalog_validator.py`, lines 22–24): `VERSION_SUFFIX_RE = re.compile(r'\.[vV]\d+')` — any entity ID containing a version suffix fails validation with `"reason": "version suffix §3.4"`. The catalog is the authoritative source; entities with version suffixes cannot be added to the taxonomy.

**WCP spec enforcement** (MEMORY.md, PyHall section): "WCP IDs: Permanent, no version suffix. `cap.doc.summarize` not `cap.doc.summarize.v1`." — Routing rules are keyed on the canonical unversioned ID. A versioned ID like `cap.doc.summarize.v1` simply does not match any rule and gets `DENY_NO_MATCHING_RULE`.

**Capability ID format validation:**

Go (`sdk/go/wcp/router.go`, lines 251–257, `validateRouteInput`): `capabilityIDRe.MatchString(input.CapabilityID)` — invalid characters return `INVALID_CAPABILITY_ID` before routing begins.

Python (`sdk/python/pyhall/router.py`): The `route_first_match` fail-closed behavior handles this — a non-matching ID is denied.

**Control character stripping** (Python router.py line 140; Go router.go line 149, `SanitizeID`; TS router.ts F16): ID fields are sanitized before writing to telemetry, preventing log injection via embedded newlines or null bytes.

**Workforce-OS note** (MEMORY.md): "Capability IDs must match routing rules seed — custom IDs fall to default deny." — The routing rules seed confirms the same fail-closed behavior in the internal workforce-os deployment.

### Severity if Defense Were Absent

**High** — Without fail-closed routing, an unknown capability ID could potentially match a catch-all rule with looser governance requirements, enabling policy gate bypass.

### Status

**MITIGATED** — Fail-closed routing (deny on no match) is enforced in all three SDKs. The catalog validator rejects version-suffixed IDs at build time. Capability ID format validation rejects malformed IDs before routing. The WCP spec's no-version-suffix rule eliminates the versioned-ID bypass vector entirely.

---

## Summary Table

| Attack | Scenario | Defense Location | Severity (if absent) | Status |
|--------|----------|-----------------|----------------------|--------|
| R1 | Hash substitution in registry | Registry access control (operator) + hash format validation at enrollment and dispatch | Critical | CONDITIONAL MITIGATED |
| R2 | Worker source tampering post-registration | `registry.compute_current_hash()` reads disk every call; full-string compare in all 3 SDKs | Critical | MITIGATED |
| R3 | Attestation field omission / injection via input | `RouteInput` has no attestation fields; `RouteDecision` attestation fields are router-set only | Critical | MITIGATED |
| R4 | Hash collision / partial hash attack | `^[0-9a-f]{64}$` regex enforces exact 64-char format; full-string equality in all 3 SDKs | High | MITIGATED |
| R5 | Unconfigured attestation fallback (nil callables) | `DENY_ATTESTATION_UNCONFIGURED` fires unconditionally when callables are missing; F2 fix | Critical | MITIGATED |
| R6 | TOCTOU race between registration and dispatch | Disk-read per call (no caching) eliminates stale-cache vector; execution gap remains | Medium | PARTIALLY MITIGATED |
| R7 | Policy gate bypass via capability ID manipulation | Fail-closed routing; catalog validator rejects version suffixes; format validation | High | MITIGATED |

**Mitigated:** 5/7
**Conditionally Mitigated:** 1/7 (R1 — depends on operator-controlled registry access control, which is by-design and documented)
**Partially Mitigated:** 1/7 (R6 — TOCTOU window between hash check and execution; inherent to library-based dispatch model)
**Vulnerable:** 0/7

---

## Cross-SDK Parity Verification

`tools/qc/sdk_parity.py` confirms the following attestation deny codes are present in all three SDKs:

| Deny Code | Python | TypeScript | Go |
|-----------|--------|------------|----|
| `DENY_WORKER_TAMPERED` | router.py:669 | router.ts:986 | router.go:722 |
| `DENY_ATTESTATION_UNCONFIGURED` | router.py:596 | router.ts:903 | router.go:572 |
| `DENY_WORKER_ATTESTATION_MISSING` | router.py:621 | router.ts:931 | router.go:609 |
| `DENY_WORKER_ATTESTATION_INVALID_HASH` | router.py:637 | router.ts:945 | router.go:645 |
| `DENY_WORKER_HASH_UNAVAILABLE` | router.py:652 | router.ts:959 | router.go:682 |

All five codes confirmed present across all three SDKs. CV-013 conformance vectors present in all three test suites.

---

## Findings Requiring Documentation / Operator Guidance

The following are not code vulnerabilities in PyHall but require operator guidance in the release documentation:

**F-OPS-1 (R1): Registry store access control**
The security of hash substitution prevention depends entirely on the operator controlling write access to the registry store. PyHall does not implement registry-level integrity protection (by design — WCP is a library, not an opinionated deployment). The release docs should prominently state: "The registry store must be write-protected. Any principal that can modify registered hashes can defeat attestation."

**F-OPS-2 (R6): TOCTOU execution gap**
Hall operators should be advised to use immutable worker deployments (container image digests, read-only mounts) as a complementary control to close the window between PyHall's hash check and worker execution.

**F-OPS-3 (general): require_worker_attestation defaults to False**
`HallConfig.require_worker_attestation=False` by default (models.py line 173). The release notes should clearly indicate that WCP-Full compliance requires this set to `True` in production. The F24 warning telemetry (`evt.os.worker.attestation_skipped`) provides runtime advisory for operators who forget, but it does not block dispatch.

---

## Overall Verdict

**GO**

The PyHall v0.1 attestation system correctly defends against 5 of 7 tested attack scenarios with no code-level vulnerabilities found. The one conditional mitigation (R1) relies on documented operator responsibilities that are consistent with WCP's explicit perimeter-based security model. The one partial mitigation (R6) is an inherent architectural constraint of a library-based dispatch protocol and is not closeable within PyHall's scope. Three operator guidance items are noted for release documentation, none of which represent release blockers.

The cross-SDK parity checker confirms all five attestation deny codes are implemented consistently across Python, TypeScript, and Go. No discrepancies found.

---

*Report generated: 2026-02-26*
*Round: 9 (final pre-release)*
*Analyst: Claude Sonnet 4.6 (FΔFΌ★LΔB)*
