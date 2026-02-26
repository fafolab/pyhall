# PyHall v0.1 Attestation + QA/QC Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship worker attestation (WCP §5.10) in all three SDKs, with a QA/QC worker fleet, catalog rebuild, and Round 9 adversarial security testing — all gated through a release checklist by March 1, 2026.

**Architecture:** Python attestation is the reference (complete). TypeScript and Go implement the same pattern: `registerAttestation()` computes SHA-256 of worker source file at enrollment; router checks current hash at dispatch; mismatch → deny. Ten QA/QC workers (Python, v0.1 architecture) execute mechanical checks. Four reasoning agents (Claude subagents) review correctness, coherence, and narrative — workers execute, agents reason. Catalog is rebuilt from a Python source-of-truth generator validated against WCP spec §3.2/§3.4.

**Tech Stack:** Python 3.12, TypeScript (Node crypto), Go 1.21 (crypto/sha256), pytest, Vitest, Go testing, SQLite, Claude subagents (feature-dev:code-reviewer)

## Two-Layer QA Architecture

```
┌─────────────────────────────────────────────────────────┐
│  REASONING AGENTS (Tasks 16-19)                         │
│  Claude subagents — read full context, reason, report   │
│  "Does this make sense? Is it correct? Does it hang?"   │
└───────────────────┬─────────────────────────────────────┘
                    │ dispatches / interprets
┌───────────────────▼─────────────────────────────────────┐
│  WORKERS (Tasks 5-12)                                   │
│  Python scripts — execute checks, produce findings      │
│  "Pattern match, count, hash, run tests"                │
└─────────────────────────────────────────────────────────┘
```

| Agent | Role | When |
|-------|------|------|
| Implementation Reviewer | Reviews TypeScript + Go attestation vs Python reference | After Tasks 1-3 |
| Worker Correctness Reviewer | Reads each QC worker and reasons about its logic | After Tasks 7-12 |
| System Coherence Reviewer | Reads full release: spec, SDKs, apps, docs — does it hang together? | After Task 13 |
| Research + Narrative Reviewer | Reviews evidence catalog, market validation, NIST draft — does the story hold? | After Task 14 |

---

## Task 1: TypeScript SDK — Attestation in Registry

**Files:**
- Modify: `sdk/typescript/src/registry.ts` (add after line 55, before enrollment section)
- Test: `sdk/typescript/tests/router.test.ts` (add attestation tests)

**Step 1: Write the failing tests**

Add to `sdk/typescript/tests/router.test.ts`:

```typescript
import { writeFileSync, unlinkSync, mkdtempSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

describe("Registry attestation (WCP §5.10)", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "pyhall-attest-"));
  });

  it("registerAttestation returns SHA-256 of file content", () => {
    const reg = new Registry();
    const workerFile = join(tmpDir, "worker.py");
    writeFileSync(workerFile, "def run(): pass\n");

    const hash = reg.registerAttestation("wrk.test.worker", workerFile);

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(reg.getWorkerHash("wrk.test.worker")).toBe(hash);
  });

  it("getCurrentWorkerHash matches registered hash when file is unchanged", () => {
    const reg = new Registry();
    const workerFile = join(tmpDir, "worker.py");
    writeFileSync(workerFile, "def run(): pass\n");

    const registered = reg.registerAttestation("wrk.test.worker", workerFile);
    const current = reg.getCurrentWorkerHash("wrk.test.worker");

    expect(current).toBe(registered);
  });

  it("getCurrentWorkerHash differs when file is mutated", () => {
    const reg = new Registry();
    const workerFile = join(tmpDir, "worker.py");
    writeFileSync(workerFile, "def run(): pass\n");

    const registered = reg.registerAttestation("wrk.test.worker", workerFile);
    writeFileSync(workerFile, "def run(): exfiltrate()\n"); // tamper

    const current = reg.getCurrentWorkerHash("wrk.test.worker");

    expect(current).not.toBe(registered);
  });

  it("getWorkerHash returns null for unknown species", () => {
    const reg = new Registry();
    expect(reg.getWorkerHash("wrk.unknown")).toBeNull();
  });

  it("getCurrentWorkerHash returns null for species with no registered file", () => {
    const reg = new Registry();
    expect(reg.getCurrentWorkerHash("wrk.unknown")).toBeNull();
  });

  it("registerAttestation throws when file does not exist", () => {
    const reg = new Registry();
    expect(() =>
      reg.registerAttestation("wrk.test.worker", "/nonexistent/worker.py")
    ).toThrow();
  });
});
```

**Step 2: Run to verify tests fail**

```bash
cd sdk/typescript && npm test -- --grep "attestation" 2>&1 | tail -20
```
Expected: FAIL — `reg.registerAttestation is not a function`

**Step 3: Implement attestation in Registry**

Add at the top of `registry.ts` (after existing imports):
```typescript
import { createHash } from "crypto";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";
```

Add private fields after line 47 (after `_capabilitiesMap`):
```typescript
  // Worker Code Attestation (WCP §5.10)
  private _attestationHashes: Map<string, string> = new Map(); // speciesId → registered SHA-256
  private _attestationFiles: Map<string, string> = new Map();  // speciesId → resolved file path
```

Add methods after the `policyAllowsPrivilege` method (before introspection section):
```typescript
  // -----------------------------------------------------------------------
  // Worker Code Attestation (WCP §5.10)
  // -----------------------------------------------------------------------

  /**
   * Register a worker's code hash by SHA-256 of its source file.
   * Call once at enrollment time to establish the known-good fingerprint.
   * Returns the hex digest.
   * Throws if the file does not exist.
   */
  registerAttestation(speciesId: string, sourceFile: string): string {
    const resolved = resolve(sourceFile);
    if (!existsSync(resolved)) {
      throw new Error(`Worker source file not found: ${sourceFile}`);
    }
    const content = readFileSync(resolved);
    const digest = createHash("sha256").update(content).digest("hex");
    this._attestationHashes.set(speciesId, digest);
    this._attestationFiles.set(speciesId, resolved);
    return digest;
  }

  /**
   * Return the registered code hash for a worker species.
   * Returns null if no attestation has been registered for this species.
   */
  getWorkerHash(speciesId: string): string | null {
    return this._attestationHashes.get(speciesId) ?? null;
  }

  /**
   * Recompute the current code hash from the worker's source file.
   * Returns null if no source file was registered for this species.
   * Call at dispatch time and compare to getWorkerHash() to detect tampering.
   */
  getCurrentWorkerHash(speciesId: string): string | null {
    const path = this._attestationFiles.get(speciesId);
    if (path === undefined) return null;
    if (!existsSync(path)) return null;
    const content = readFileSync(path);
    return createHash("sha256").update(content).digest("hex");
  }
```

**Step 4: Run tests to verify they pass**

```bash
cd sdk/typescript && npm test -- --grep "attestation" 2>&1 | tail -20
```
Expected: 6 tests PASS

**Step 5: Run full TypeScript test suite to check no regressions**

```bash
cd sdk/typescript && npm test 2>&1 | tail -5
```
Expected: 83+ tests PASS

**Step 6: Commit**

```bash
git add sdk/typescript/src/registry.ts sdk/typescript/tests/router.test.ts
git commit -m "feat(ts): implement worker code attestation in Registry (WCP §5.10)"
```

---

## Task 2: TypeScript SDK — Wire Attestation into Router

**Files:**
- Modify: `sdk/typescript/src/router.ts:624-640` (replace stub with real check)
- Test: `sdk/typescript/tests/router.test.ts` (router-level attestation tests)

**Step 1: Read the current stub**

Open `sdk/typescript/src/router.ts` around lines 624-640. You will see:
```typescript
if (preChecked.deny_if_no_attestation_in_prod === true && hallConfig?.requireWorkerAttestation === true) {
  return _deny("DENY_ATTESTATION_NOT_IMPLEMENTED", "deny_if_no_attestation_in_prod=true is set but attestation enforcement is not yet implemented. ...");
}
```

**Step 2: Write the failing router-level test**

Add to `sdk/typescript/tests/router.test.ts`:

```typescript
describe("Router attestation enforcement", () => {
  it("dispatches successfully when attestation matches", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "pyhall-router-attest-"));
    const workerFile = join(tmpDir, "greeter.py");
    writeFileSync(workerFile, "def run(): pass\n");

    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.greeter",
      worker_species_id: "wrk.hello.greeter",
      capabilities: ["cap.hello.greet"],
      risk_tier: "low",
      currently_implements: ["ctrl.obs.audit-log-append-only"],
      required_controls: ["ctrl.obs.audit-log-append-only"],
      allowed_environments: ["dev"],
    });
    registry.registerAttestation("wrk.hello.greeter", workerFile);

    const input = makeInput({ capability_id: "cap.hello.greet" });
    const rules = makeRules("cap.hello.greet", "wrk.hello.greeter");
    const hallConfig = { requireWorkerAttestation: true };

    const decision = makeDecision(input, rules, {
      registry,
      hallConfig,
      registryGetWorkerHash: (s) => registry.getWorkerHash(s),
      getCurrentWorkerHash: (s) => registry.getCurrentWorkerHash(s),
    });

    expect(decision.denied).toBe(false);
    expect(decision.worker_attestation_checked).toBe(true);
    expect(decision.worker_attestation_valid).toBe(true);
  });

  it("denies with DENY_WORKER_TAMPERED when file is mutated", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "pyhall-router-tamper-"));
    const workerFile = join(tmpDir, "greeter.py");
    writeFileSync(workerFile, "def run(): pass\n");

    const registry = new Registry();
    registry.enroll({
      worker_id: "org.test.greeter",
      worker_species_id: "wrk.hello.greeter",
      capabilities: ["cap.hello.greet"],
      risk_tier: "low",
      currently_implements: ["ctrl.obs.audit-log-append-only"],
      required_controls: ["ctrl.obs.audit-log-append-only"],
      allowed_environments: ["dev"],
    });
    registry.registerAttestation("wrk.hello.greeter", workerFile);

    // Tamper with the worker file
    writeFileSync(workerFile, "def run(): exfiltrate()\n");

    const input = makeInput({ capability_id: "cap.hello.greet" });
    const rules = makeRules("cap.hello.greet", "wrk.hello.greeter");
    const hallConfig = { requireWorkerAttestation: true };

    const decision = makeDecision(input, rules, {
      registry,
      hallConfig,
      registryGetWorkerHash: (s) => registry.getWorkerHash(s),
      getCurrentWorkerHash: (s) => registry.getCurrentWorkerHash(s),
    });

    expect(decision.denied).toBe(true);
    expect(decision.deny_reason_if_denied?.code).toBe("DENY_WORKER_TAMPERED");
    expect(decision.worker_attestation_checked).toBe(true);
    expect(decision.worker_attestation_valid).toBe(false);
  });
});
```

**Step 3: Run to verify tests fail**

```bash
cd sdk/typescript && npm test -- --grep "Router attestation" 2>&1 | tail -10
```
Expected: FAIL

**Step 4: Replace the stub in router.ts**

Find the stub block at lines ~624-640 and replace it with:

```typescript
  // Worker Code Attestation (WCP §5.10)
  // When requireWorkerAttestation is enabled, verify the selected worker's
  // code hash matches the registered fingerprint before dispatch.
  if (hallConfig?.requireWorkerAttestation === true && selectedSpecies) {
    const registeredHash = opts?.registryGetWorkerHash
      ? opts.registryGetWorkerHash(selectedSpecies)
      : null;
    const currentHash = opts?.getCurrentWorkerHash
      ? opts.getCurrentWorkerHash(selectedSpecies)
      : null;

    decision.worker_attestation_checked = true;

    if (registeredHash === null) {
      decision.worker_attestation_valid = false;
      return _deny("DENY_ATTESTATION_UNCONFIGURED",
        `requireWorkerAttestation is true but no attestation hash is registered for species '${selectedSpecies}'.`);
    }

    if (currentHash === null || currentHash !== registeredHash) {
      decision.worker_attestation_valid = false;
      decision.deny_reason_if_denied = {
        code: "DENY_WORKER_TAMPERED",
        message: "Worker code hash mismatch. Worker may have been modified after attestation.",
        worker_species_id: selectedSpecies,
        registered_hash: registeredHash,
        current_hash: currentHash,
      };
      decision.denied = true;
      return decision;
    }

    decision.worker_attestation_valid = true;
  }
```

Also add the callback types to the `makeDecision` options interface (find the `MakeDecisionOptions` or equivalent type and add):
```typescript
  registryGetWorkerHash?: (speciesId: string) => string | null;
  getCurrentWorkerHash?: (speciesId: string) => string | null;
```

**Step 5: Run router attestation tests**

```bash
cd sdk/typescript && npm test -- --grep "Router attestation" 2>&1 | tail -10
```
Expected: 2 tests PASS

**Step 6: Run full suite**

```bash
cd sdk/typescript && npm test 2>&1 | tail -5
```
Expected: 85+ tests PASS

**Step 7: Commit**

```bash
git add sdk/typescript/src/router.ts sdk/typescript/tests/router.test.ts
git commit -m "feat(ts): wire worker attestation into router (WCP §5.10)"
```

---

## Task 3: Go SDK — Attestation in Registry

**Files:**
- Modify: `sdk/go/wcp/registry.go` (add attestation fields + methods)
- Modify: `sdk/go/wcp/router.go` (wire attestation check into MakeDecision)
- Test: `sdk/go/wcp/router_test.go` (add attestation tests)

**Step 1: Write failing tests**

Add to `sdk/go/wcp/router_test.go`:

```go
import (
    "os"
    "path/filepath"
    "testing"
)

func TestAttestationMatch(t *testing.T) {
    dir := t.TempDir()
    workerFile := filepath.Join(dir, "worker.py")
    if err := os.WriteFile(workerFile, []byte("def run(): pass\n"), 0644); err != nil {
        t.Fatal(err)
    }

    reg := NewRegistry()
    if err := reg.Enroll(WorkerRegistryRecord{
        WorkerID:            "org.test.greeter",
        WorkerSpeciesID:     "wrk.hello.greeter",
        Capabilities:        []string{"cap.hello.greet"},
        RiskTier:            "low",
        CurrentlyImplements: []string{"ctrl.obs.audit-log-append-only"},
        RequiredControls:    []string{"ctrl.obs.audit-log-append-only"},
        AllowedEnvironments: []string{"dev"},
    }); err != nil {
        t.Fatal(err)
    }
    if _, err := reg.RegisterAttestation("wrk.hello.greeter", workerFile); err != nil {
        t.Fatal(err)
    }

    input := RouteInput{
        CapabilityID: "cap.hello.greet",
        Env:          EnvDev,
        DataLabel:    DataLabelPublic,
        TenantRisk:   TenantRiskLow,
        QoSClass:     QoSClassP2,
        TenantID:     "test.tenant",
        CorrelationID: "test-corr-id",
    }
    rules := []RoutingRule{{
        RuleID:              "rr_test",
        CapabilityID:        "cap.hello.greet",
        WorkerSpeciesID:     "wrk.hello.greeter",
        RequiredControls:    []string{"ctrl.obs.audit-log-append-only"},
    }}

    decision, err := MakeDecision(input, rules, reg, MakeDecisionOpts{
        HallConfig: &HallConfig{RequireWorkerAttestation: true},
    })
    if err != nil {
        t.Fatal(err)
    }
    if decision.Denied {
        t.Errorf("expected dispatch, got DENY: %v", decision.DenyReasonIfDenied)
    }
    if !decision.WorkerAttestationChecked {
        t.Error("expected WorkerAttestationChecked=true")
    }
    if !decision.WorkerAttestationValid {
        t.Error("expected WorkerAttestationValid=true")
    }
}

func TestAttestationTamper(t *testing.T) {
    dir := t.TempDir()
    workerFile := filepath.Join(dir, "worker.py")
    if err := os.WriteFile(workerFile, []byte("def run(): pass\n"), 0644); err != nil {
        t.Fatal(err)
    }

    reg := NewRegistry()
    _ = reg.Enroll(WorkerRegistryRecord{
        WorkerID:            "org.test.greeter",
        WorkerSpeciesID:     "wrk.hello.greeter",
        Capabilities:        []string{"cap.hello.greet"},
        RiskTier:            "low",
        CurrentlyImplements: []string{"ctrl.obs.audit-log-append-only"},
        RequiredControls:    []string{"ctrl.obs.audit-log-append-only"},
        AllowedEnvironments: []string{"dev"},
    })
    reg.RegisterAttestation("wrk.hello.greeter", workerFile)

    // Tamper
    os.WriteFile(workerFile, []byte("def run(): exfiltrate()\n"), 0644)

    input := RouteInput{
        CapabilityID:  "cap.hello.greet",
        Env:           EnvDev,
        DataLabel:     DataLabelPublic,
        TenantRisk:    TenantRiskLow,
        QoSClass:      QoSClassP2,
        TenantID:      "test.tenant",
        CorrelationID: "test-corr-id",
    }
    rules := []RoutingRule{{
        RuleID:           "rr_test",
        CapabilityID:     "cap.hello.greet",
        WorkerSpeciesID:  "wrk.hello.greeter",
        RequiredControls: []string{"ctrl.obs.audit-log-append-only"},
    }}

    decision, _ := MakeDecision(input, rules, reg, MakeDecisionOpts{
        HallConfig: &HallConfig{RequireWorkerAttestation: true},
    })

    if !decision.Denied {
        t.Error("expected DENY for tampered worker")
    }
    if decision.DenyReasonIfDenied == nil || decision.DenyReasonIfDenied["code"] != "DENY_WORKER_TAMPERED" {
        t.Errorf("expected DENY_WORKER_TAMPERED, got %v", decision.DenyReasonIfDenied)
    }
    if decision.WorkerAttestationValid {
        t.Error("expected WorkerAttestationValid=false")
    }
}
```

**Step 2: Run to verify tests fail**

```bash
cd sdk/go && go test ./wcp/... -run "TestAttestation" -v 2>&1 | tail -10
```
Expected: FAIL — `reg.RegisterAttestation undefined`

**Step 3: Add attestation fields to Registry struct**

In `sdk/go/wcp/registry.go`, modify the `Registry` struct and `NewRegistry()`:

```go
type Registry struct {
    mu               sync.RWMutex
    workers          map[string]WorkerRegistryRecord
    attestationHashes map[string]string // speciesID → registered SHA-256
    attestationFiles  map[string]string // speciesID → source file path
}

func NewRegistry() *Registry {
    return &Registry{
        workers:           make(map[string]WorkerRegistryRecord),
        attestationHashes: make(map[string]string),
        attestationFiles:  make(map[string]string),
    }
}
```

Add these three methods at the end of `registry.go`:

```go
// RegisterAttestation records the SHA-256 of a worker's source file as the
// known-good fingerprint. Call once at enrollment time.
// Returns the hex digest or error if the file cannot be read.
func (r *Registry) RegisterAttestation(speciesID, sourceFile string) (string, error) {
    content, err := os.ReadFile(sourceFile)
    if err != nil {
        return "", RegistryError{Op: "register_attestation", Msg: err.Error()}
    }
    sum := sha256.Sum256(content)
    digest := hex.EncodeToString(sum[:])
    r.mu.Lock()
    defer r.mu.Unlock()
    r.attestationHashes[speciesID] = digest
    r.attestationFiles[speciesID] = sourceFile
    return digest, nil
}

// GetWorkerHash returns the registered attestation hash for a species.
// Returns ("", false) if no attestation has been registered.
func (r *Registry) GetWorkerHash(speciesID string) (string, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    h, ok := r.attestationHashes[speciesID]
    return h, ok
}

// GetCurrentWorkerHash recomputes the hash of the worker's source file.
// Returns ("", false, nil) if no source file was registered.
// Returns ("", true, err) if the file cannot be read.
// Returns (hash, true, nil) on success.
func (r *Registry) GetCurrentWorkerHash(speciesID string) (string, bool, error) {
    r.mu.RLock()
    path, ok := r.attestationFiles[speciesID]
    r.mu.RUnlock()
    if !ok {
        return "", false, nil
    }
    content, err := os.ReadFile(path)
    if err != nil {
        return "", true, err
    }
    sum := sha256.Sum256(content)
    return hex.EncodeToString(sum[:]), true, nil
}
```

Add required imports to `registry.go`:
```go
import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"
    "sync"
)
```

**Step 4: Add attestation fields to RouteDecision and wire into router**

In `sdk/go/wcp/models.go`, add to `RouteDecision` struct:
```go
WorkerAttestationChecked bool        `json:"worker_attestation_checked"`
WorkerAttestationValid   bool        `json:"worker_attestation_valid"`
```

In `sdk/go/wcp/router.go`, find `HallConfig` and add:
```go
RequireWorkerAttestation bool `json:"require_worker_attestation"`
```

Then add the attestation check in `MakeDecision` after the worker is selected (after blast/privilege checks, before final dispatch):

```go
// Worker Code Attestation (WCP §5.10)
if opts.HallConfig != nil && opts.HallConfig.RequireWorkerAttestation && selectedSpeciesID != "" {
    decision.WorkerAttestationChecked = true
    registeredHash, hasHash := registry.GetWorkerHash(selectedSpeciesID)
    if !hasHash {
        decision.WorkerAttestationValid = false
        decision.Denied = true
        decision.DenyReasonIfDenied = map[string]any{
            "code":    "DENY_ATTESTATION_UNCONFIGURED",
            "message": fmt.Sprintf("requireWorkerAttestation is true but no attestation hash registered for species '%s'", selectedSpeciesID),
        }
        return decision, nil
    }
    currentHash, _, err := registry.GetCurrentWorkerHash(selectedSpeciesID)
    if err != nil || currentHash != registeredHash {
        decision.WorkerAttestationValid = false
        decision.Denied = true
        decision.DenyReasonIfDenied = map[string]any{
            "code":              "DENY_WORKER_TAMPERED",
            "message":           "Worker code hash mismatch. Worker may have been modified after attestation.",
            "worker_species_id": selectedSpeciesID,
            "registered_hash":   registeredHash,
            "current_hash":      currentHash,
        }
        return decision, nil
    }
    decision.WorkerAttestationValid = true
}
```

**Step 5: Run attestation tests**

```bash
cd sdk/go && go test ./wcp/... -run "TestAttestation" -v 2>&1 | tail -15
```
Expected: 2 tests PASS

**Step 6: Run full Go test suite**

```bash
cd sdk/go && go test ./... 2>&1 | tail -5
```
Expected: all PASS

**Step 7: Commit**

```bash
git add sdk/go/wcp/registry.go sdk/go/wcp/router.go sdk/go/wcp/models.go sdk/go/wcp/router_test.go
git commit -m "feat(go): implement worker code attestation in Registry and router (WCP §5.10)"
```

---

## Task 4: CV-013 — Cross-SDK Conformance Vector

**Files:**
- Modify: `docs/conformance/wcp_conformance_vectors.json` (add CV-013)
- Modify: `sdk/python/tests/test_conformance.py` (add CV-013 test)
- Modify: `sdk/typescript/tests/conformance.test.ts` (add CV-013 test)
- Modify: `sdk/go/wcp/conformance_test.go` (add CV-013 test)

**Step 1: Add CV-013 to the conformance vectors JSON**

Open `docs/conformance/wcp_conformance_vectors.json` and add:

```json
{
  "id": "CV-013",
  "description": "Worker attestation: enroll with hash, verify match, mutate file, verify DENY_WORKER_TAMPERED",
  "category": "attestation",
  "release_blocking": true,
  "steps": [
    "Enroll worker with attestation registered (SHA-256 of source file)",
    "Dispatch capability → verify worker_attestation_valid=true, denied=false",
    "Mutate the worker source file (change one byte)",
    "Dispatch again → verify denied=true, code=DENY_WORKER_TAMPERED",
    "Verify evidence receipt includes registered_hash, current_hash, worker_attestation_checked=true"
  ],
  "expected_deny_code": "DENY_WORKER_TAMPERED"
}
```

**Step 2: Add Python CV-013 test**

Add to `sdk/python/tests/test_conformance.py`:

```python
def test_cv013_worker_attestation(tmp_path):
    """CV-013: Worker attestation — enroll, verify, tamper, deny."""
    worker_file = tmp_path / "worker.py"
    worker_file.write_text("def run(): pass\n")

    registry = Registry()
    registry.enroll({
        "worker_id": "org.test.cv013",
        "worker_species_id": "wrk.test.cv013",
        "capabilities": ["cap.test.cv013"],
        "risk_tier": "low",
        "required_controls": ["ctrl.obs.audit-log-append-only"],
        "currently_implements": ["ctrl.obs.audit-log-append-only"],
        "allowed_environments": ["dev"],
    })
    registry.register_attestation("wrk.test.cv013", str(worker_file))

    rules = [RoutingRule(
        rule_id="rr_cv013",
        capability_id="cap.test.cv013",
        worker_species_id="wrk.test.cv013",
        required_controls=["ctrl.obs.audit-log-append-only"],
    )]
    hall_config = HallConfig(require_worker_attestation=True)
    base_input = RouteInput(
        capability_id="cap.test.cv013",
        env="dev", data_label="PUBLIC",
        tenant_risk="low", qos_class="P2",
        tenant_id="test.tenant", correlation_id="cv013",
    )

    # Step 2: dispatch with intact file → PASS
    decision = make_decision(
        base_input, rules,
        registry_get_worker_hash=registry.get_worker_hash,
        get_current_worker_hash=registry.get_current_worker_hash,
        hall_config=hall_config,
    )
    assert not decision.denied
    assert decision.worker_attestation_checked
    assert decision.worker_attestation_valid

    # Step 3: tamper
    worker_file.write_text("def run(): exfiltrate()\n")

    # Step 4: dispatch with tampered file → DENY_WORKER_TAMPERED
    decision2 = make_decision(
        base_input, rules,
        registry_get_worker_hash=registry.get_worker_hash,
        get_current_worker_hash=registry.get_current_worker_hash,
        hall_config=hall_config,
    )
    assert decision2.denied
    assert decision2.deny_reason_if_denied["code"] == "DENY_WORKER_TAMPERED"
    assert decision2.worker_attestation_checked
    assert not decision2.worker_attestation_valid
    assert "registered_hash" in decision2.deny_reason_if_denied
    assert "current_hash" in decision2.deny_reason_if_denied
```

**Step 3: Run all three conformance suites**

```bash
cd sdk/python && python -m pytest tests/test_conformance.py -v 2>&1 | tail -10
cd sdk/typescript && npm test -- --grep "CV-013" 2>&1 | tail -10
cd sdk/go && go test ./wcp/... -run "CV013" -v 2>&1 | tail -10
```
Expected: All PASS

**Step 4: Commit**

```bash
git add docs/conformance/wcp_conformance_vectors.json \
        sdk/python/tests/test_conformance.py \
        sdk/typescript/tests/conformance.test.ts \
        sdk/go/wcp/conformance_test.go
git commit -m "test: add CV-013 cross-SDK worker attestation conformance vector"
```

---

## Task 5: Catalog Rebuild

**Files:**
- Create: `scripts/build_catalog.py`
- Create: `taxonomy/src/` (one .py file per pack)
- Modify: `sdk/python/pyhall/taxonomy/catalog.json` (output of generator)

**Step 1: Create the generator script**

Create `scripts/build_catalog.py`:

```python
#!/usr/bin/env python3
"""
build_catalog.py — Generate catalog.json from taxonomy source files.

Validates all entity IDs against WCP spec §3.2/§3.4 before writing.
Fails with exit code 1 if any entity violates spec rules.

Usage: python scripts/build_catalog.py
Output: sdk/python/pyhall/taxonomy/catalog.json (and 3 other sync locations)
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
CATALOG_PATHS = [
    ROOT / "sdk/python/pyhall/taxonomy/catalog.json",
    ROOT / "sdk/typescript/src/taxonomy/catalog.json",
    ROOT / "sdk/go/wcp/taxonomy/catalog.json",
    ROOT / "web/playground/data/catalog.json",
]

# WCP spec §3.2: 2-4 dot-separated segments, lowercase a-z/digits/hyphens only.
# §3.4: No version numbers in IDs (no .v1, .v2, etc.).
VALID_ID_RE = re.compile(r'^[a-z][a-z0-9\-]*(\.[a-z][a-z0-9\-]*){1,3}$')
VERSION_SUFFIX_RE = re.compile(r'\.[vV]\d+')

def validate_id(entity_id: str) -> list[str]:
    errors = []
    if not VALID_ID_RE.match(entity_id):
        errors.append(f"  ID '{entity_id}' fails format check (spec §3.2): must be 2-4 dot-separated lowercase segments, no underscores")
    if VERSION_SUFFIX_RE.search(entity_id):
        errors.append(f"  ID '{entity_id}' contains version suffix (spec §3.4): remove .v1, .v2, etc.")
    return errors

def load_sources() -> tuple[list[dict], list[dict]]:
    """Load all pack and entity definitions from taxonomy/src/."""
    src_dir = ROOT / "taxonomy/src"
    packs = []
    entities = []
    for src_file in sorted(src_dir.glob("pack_*.py")):
        namespace = {}
        exec(src_file.read_text(), namespace)
        packs.extend(namespace.get("PACKS", []))
        entities.extend(namespace.get("ENTITIES", []))
    return packs, entities

def main():
    packs, entities = load_sources()
    errors = []
    for entity in entities:
        errors.extend(validate_id(entity["id"]))

    if errors:
        print(f"CATALOG BUILD FAILED — {len(errors)} spec violations:\n")
        for e in errors:
            print(e)
        sys.exit(1)

    catalog = {
        "_meta": {
            "version": "0.1.0",
            "wcp_spec": "0.1-DRAFT",
            "total_entities": len(entities),
            "packs": len(packs),
            "generated_from": "taxonomy/src/pack_*.py",
            "built": __import__("datetime").date.today().isoformat(),
        },
        "packs": packs,
        "entities": entities,
    }

    for dest in CATALOG_PATHS:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(catalog, indent=2) + "\n")
        print(f"  wrote {dest.relative_to(ROOT)}")

    print(f"\nCatalog built: {len(entities)} entities across {len(packs)} packs.")

if __name__ == "__main__":
    main()
```

**Step 2: Create taxonomy source files**

Create `taxonomy/src/pack_01_sandboxing.py` as the model pack (the rest follow the same pattern):

```python
"""Pack 01 — Sandboxing & Containment"""

PACKS = [
    {
        "id": "pack.01",
        "name": "Sandboxing & Containment",
        "description": "Controls and capabilities for executing workers in isolated environments.",
    }
]

ENTITIES = [
    {
        "id": "cap.sandbox.exec-isolated",
        "type": "capability",
        "pack_id": "pack.01",
        "name": "Execute Isolated",
        "description": "Execute a worker inside a sandbox boundary with restricted OS access.",
        "risk_tier": "medium",
        "blast_radius_hint": {"data": 1, "network": 0, "financial": 0, "time": 1, "reversibility": "reversible"},
        "typical_controls": ["ctrl.sandbox.no-egress-default-deny", "ctrl.sandbox.readonly-rootfs"],
        "idempotency": "full",
        "determinism": "deterministic",
        "tags": ["sandbox", "execution"],
        "wcp_namespace": "reserved",
    },
    # ... (add all 19 pack.01 entities following this schema)
    {
        "id": "ctrl.sandbox.no-egress-default-deny",
        "type": "control",
        "pack_id": "pack.01",
        "name": "No Egress Default Deny",
        "description": "Disable all outbound network by default; egress requires explicit allowlist.",
        "enforcement_point": "worker",
        "required_for_risk_tiers": ["medium", "high"],
        "tags": ["sandbox", "network", "safety"],
        "wcp_namespace": "reserved",
    },
]
```

Note: Complete all 27 pack files. Each entity ID must pass `validate_id()` — no `.v1`, no underscores in IDs, 2-4 segments, lowercase only.

**Step 3: Build and verify**

```bash
cd /mnt/fafolab/dev/pyhall/git && python scripts/build_catalog.py
```
Expected: "Catalog built: N entities across 27 packs." with zero violations.

**Step 4: Verify sync locations all received the file**

```bash
md5sum sdk/python/pyhall/taxonomy/catalog.json \
       sdk/typescript/src/taxonomy/catalog.json \
       web/playground/data/catalog.json
```
Expected: all three hashes match.

**Step 5: Run CLI tests that reference catalog entities**

```bash
cd sdk/python && python -m pytest tests/test_cli_user.py -v 2>&1 | tail -10
```
Fix any test references to old `.v1` IDs.

**Step 6: Commit**

```bash
git add scripts/build_catalog.py taxonomy/src/ sdk/python/pyhall/taxonomy/catalog.json \
        sdk/typescript/src/taxonomy/catalog.json web/playground/data/catalog.json
git commit -m "feat: catalog rebuild from authoritative spec schema (spec §3.2/§3.4 compliant)"
```

---

## Task 6: pyhall_audit.db — Local Hash-Chained Audit Database

**Files:**
- Create: `tools/audit/setup_audit_db.py`
- Create: `tools/audit/audit_writer.py`

**Step 1: Create the DB setup script**

Create `tools/audit/setup_audit_db.py`:

```python
"""
setup_audit_db.py — Initialize pyhall_audit.db with hash-chained tables.

Run once: python tools/audit/setup_audit_db.py
DB location: /mnt/fafolab/dev/pyhall/pyhall_audit.db (never in git)
"""
import hashlib
import sqlite3
from datetime import datetime, UTC
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent.parent / "pyhall_audit.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS attestation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id TEXT NOT NULL,
    species_id TEXT NOT NULL,
    registered_hash TEXT,
    current_hash TEXT,
    matched INTEGER NOT NULL,  -- 1=match, 0=mismatch
    checked_at TEXT NOT NULL,  -- ISO8601 UTC
    entry_hash TEXT NOT NULL   -- hash chain
);

CREATE TABLE IF NOT EXISTS qc_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id TEXT NOT NULL,
    run_at TEXT NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    passed INTEGER NOT NULL,  -- 1=pass, 0=fail
    report_path TEXT,
    entry_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS qc_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES qc_runs(id),
    severity TEXT NOT NULL CHECK(severity IN ('info', 'warning', 'error')),
    file_path TEXT,
    finding_type TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hash_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_hash TEXT NOT NULL UNIQUE,
    previous_hash TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    entry_type TEXT NOT NULL,  -- attestation_log | qc_runs
    entry_id INTEGER NOT NULL
);
"""

def main():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"pyhall_audit.db initialized at {DB_PATH}")

if __name__ == "__main__":
    main()
```

Create `tools/audit/audit_writer.py`:

```python
"""audit_writer.py — Write hash-chained entries to pyhall_audit.db."""
import hashlib
import json
import sqlite3
from datetime import datetime, UTC
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent.parent / "pyhall_audit.db"

def _get_previous_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT entry_hash FROM hash_chain ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else "0" * 64

def _chain_hash(content: dict, previous_hash: str, timestamp: str) -> str:
    data = json.dumps(content, sort_keys=True) + previous_hash + timestamp
    return hashlib.sha256(data.encode()).hexdigest()

def write_attestation(correlation_id: str, species_id: str,
                      registered_hash: str | None, current_hash: str | None,
                      matched: bool) -> str:
    """Write an attestation check result to the audit log. Returns entry_hash."""
    conn = sqlite3.connect(DB_PATH)
    ts = datetime.now(UTC).isoformat()
    previous = _get_previous_hash(conn)
    content = {
        "type": "attestation_log",
        "correlation_id": correlation_id,
        "species_id": species_id,
        "registered_hash": registered_hash,
        "current_hash": current_hash,
        "matched": matched,
    }
    entry_hash = _chain_hash(content, previous, ts)
    cursor = conn.execute(
        "INSERT INTO attestation_log (correlation_id, species_id, registered_hash, current_hash, matched, checked_at, entry_hash) VALUES (?,?,?,?,?,?,?)",
        (correlation_id, species_id, registered_hash, current_hash, int(matched), ts, entry_hash)
    )
    entry_id = cursor.lastrowid
    conn.execute(
        "INSERT INTO hash_chain (entry_hash, previous_hash, timestamp, entry_type, entry_id) VALUES (?,?,?,?,?)",
        (entry_hash, previous, ts, "attestation_log", entry_id)
    )
    conn.commit()
    conn.close()
    return entry_hash
```

**Step 2: Initialize the DB**

```bash
python tools/audit/setup_audit_db.py
```
Expected: "pyhall_audit.db initialized at /mnt/fafolab/dev/pyhall/pyhall_audit.db"

**Step 3: Verify DB is excluded from git**

```bash
cd /mnt/fafolab/dev/pyhall/git && git status --short | grep audit
```
Expected: pyhall_audit.db does NOT appear (it's in the parent directory, outside git/).

**Step 4: Commit**

```bash
git add tools/audit/setup_audit_db.py tools/audit/audit_writer.py
git commit -m "feat: pyhall_audit.db hash-chained audit trail setup"
```

---

## Task 7: QA/QC Worker Fleet

**Files:**
- Create: `tools/qc/catalog_validator.py`
- Create: `tools/qc/stale_scanner.py`
- Create: `tools/qc/sdk_parity.py`
- Create: `tools/qc/release_gate.py`
- Create: `tools/qc/registry_records/` (one JSON per worker)

Each worker follows the v0.1 pyhall SDK pattern: `registry_record.json` + `worker.py` with a `run(ctx, request)` function.

**Step 1: catalog_validator.py**

```python
"""
cap.qc.catalog.validate — Validate catalog.json against WCP spec §3.2/§3.4.
Writes findings to pyhall_audit.db.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

VALID_ID_RE = re.compile(r'^[a-z][a-z0-9\-]*(\.[a-z][a-z0-9\-]*){1,3}$')
VERSION_SUFFIX_RE = re.compile(r'\.[vV]\d+')

def run(ctx, request):
    catalog_path = ROOT / "sdk/python/pyhall/taxonomy/catalog.json"
    catalog = json.loads(catalog_path.read_text())
    findings = []
    for entity in catalog.get("entities", []):
        eid = entity.get("id", "")
        if not VALID_ID_RE.match(eid):
            findings.append({"severity": "error", "id": eid, "reason": "format violation §3.2"})
        if VERSION_SUFFIX_RE.search(eid):
            findings.append({"severity": "error", "id": eid, "reason": "version suffix §3.4"})
    return {
        "passed": len(findings) == 0,
        "total_entities": len(catalog.get("entities", [])),
        "violations": findings,
    }
```

**Step 2: stale_scanner.py**

```python
"""
cap.qc.stale.scan — Scan the monorepo for unused/stale files.
Outputs archive candidates with rationale.
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

STALE_PATTERNS = [
    ("lab/workforce-os", "Predates v0.1 security rounds; outdated worker architecture"),
    ("**/*.v1.*", "Files containing legacy .v1 naming"),
    ("**/*_old.*", "Explicitly named old versions"),
    ("**/*_backup.*", "Backup files"),
]

def run(ctx, request):
    archive_candidates = []
    for pattern, reason in STALE_PATTERNS:
        if "/" in pattern and not pattern.startswith("**"):
            target = ROOT / pattern
            if target.exists():
                archive_candidates.append({
                    "path": str(target.relative_to(ROOT.parent)),
                    "reason": reason,
                    "action": "archive",
                })
        else:
            for match in ROOT.glob(pattern):
                if ".git" not in str(match):
                    archive_candidates.append({
                        "path": str(match.relative_to(ROOT.parent)),
                        "reason": reason,
                        "action": "archive",
                    })
    return {
        "passed": True,  # scanner never fails — it reports
        "archive_candidates": archive_candidates,
        "count": len(archive_candidates),
    }
```

**Step 3: release_gate.py**

```python
"""
cap.qc.release.check — Run full test suite + conformance vectors, generate go/no-go report.
"""
import subprocess
import json
from pathlib import Path
from datetime import datetime, UTC

ROOT = Path(__file__).parent.parent.parent

def _run(cmd, cwd):
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return result.returncode == 0, result.stdout + result.stderr

def run(ctx, request):
    results = {}

    results["python_tests"], out = _run(["python", "-m", "pytest", "tests/", "-q"], ROOT / "sdk/python")
    results["python_output"] = out[-500:]

    results["typescript_tests"], out = _run(["npm", "test", "--", "--reporter=min"], ROOT / "sdk/typescript")
    results["typescript_output"] = out[-500:]

    results["go_tests"], out = _run(["go", "test", "./..."], ROOT / "sdk/go")
    results["go_output"] = out[-500:]

    passed = all(results[k] for k in ["python_tests", "typescript_tests", "go_tests"])
    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "passed": passed,
        "results": results,
    }

    report_path = ROOT.parent / "release/qa-reports" / f"release-gate-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    report["report_path"] = str(report_path)
    return report
```

**Step 4: Run the QC workers manually to verify they execute**

```bash
cd /mnt/fafolab/dev/pyhall/git
python -c "
import sys; sys.path.insert(0, 'sdk/python')
from tools.qc.catalog_validator import run
result = run({}, {})
print('Catalog validator:', 'PASS' if result['passed'] else 'FAIL', f\"({result['total_entities']} entities, {len(result['violations'])} violations)\")
"
```
Expected: PASS with 0 violations (after catalog rebuild).

**Step 5: Commit**

```bash
git add tools/qc/
git commit -m "feat: QA/QC worker fleet (catalog, stale-scanner, sdk-parity, release-gate)"
```

---

## Task 8: QA/QC — CLI Apps (All 3 Languages)

**Files:**
- Create: `tools/qc/cli_validator.py`
- Scope: `apps/cli/typescript/`, `sdk/python/pyhall/cli.py`, `sdk/go/cmd/pyhall/`

**What gets checked:**
- All 3 CLIs respond to: `version`, `search`, `explain`, `browse`, `scaffold`
- `search` and `browse` return results from the rebuilt catalog (no `.v1` IDs in output)
- `scaffold` generates registry records with correct field schema (14 fields, no `.v1` in IDs)
- Existing test counts hold: Python CLI 105 pass, TypeScript CLI 36 pass, Go CLI 5 pass
- Help text contains no `.v1` references

**Step 1: Run all three CLI test suites**

```bash
# Python CLI
cd sdk/python && python -m pytest tests/test_cli_user.py -v 2>&1 | tail -15

# TypeScript CLI
cd apps/cli/typescript && npm test 2>&1 | tail -10

# Go CLI
cd sdk/go && go test ./cmd/pyhall/... -v 2>&1 | tail -10
```
Expected: Python 105 pass, TypeScript 36 pass, Go 5 pass.

**Step 2: Smoke test each CLI command against rebuilt catalog**

```bash
# Python
pyhall search "document summarize" | grep -v "\.v1"
pyhall explain cap.doc.summarize | grep -v "\.v1"
pyhall scaffold --capability cap.doc.summarize --worker wrk.doc.summarizer --species wrk.doc.summarizer

# TypeScript
pyhall search "document" | grep -v "\.v1"

# Go
pyhall version
pyhall search document | grep -v "\.v1"
```
Expected: no `.v1` appears in any CLI output.

**Step 3: Check CLI help text for `.v1` references**

```bash
grep -r "\.v[0-9]" sdk/python/pyhall/cli.py apps/cli/typescript/src/ sdk/go/cmd/
```
Expected: zero matches. If any found, fix them — they are leftover from the old taxonomy.

**Step 4: Create the CLI QC worker**

Create `tools/qc/cli_validator.py`:

```python
"""cap.qc.cli.validate — Validate all 3 CLIs against rebuilt catalog."""
import subprocess
import re

V1_RE = re.compile(r'\.[vV]\d+')

def _check_no_v1(output: str) -> list[str]:
    return [line for line in output.splitlines() if V1_RE.search(line)]

def run(ctx, request):
    findings = []

    # Python CLI smoke tests
    for cmd in [["python", "-m", "pyhall", "version"],
                ["python", "-m", "pyhall", "search", "document"]]:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd="sdk/python")
        if result.returncode != 0:
            findings.append({"severity": "error", "cmd": " ".join(cmd), "detail": result.stderr})
        violations = _check_no_v1(result.stdout)
        for v in violations:
            findings.append({"severity": "error", "cmd": " ".join(cmd), "detail": f".v1 in output: {v}"})

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "findings": findings,
    }
```

**Step 5: Commit**

```bash
git add tools/qc/cli_validator.py
git commit -m "feat(qc): CLI validator worker for all 3 language CLIs"
```

---

## Task 9: QA/QC — pyhall.dev Website

**Files:**
- Create: `tools/qc/web_validator.py`
- Scope: `web/index.html`, `web/blog/the-governance-gap.html`

**What gets checked:**
- Entity IDs displayed on site match catalog (no `.v1`)
- Entity count in site copy matches `catalog._meta.total_entities`
- `#0050D4` blue theme present in CSS (branding check)
- Blog post entity ID references are valid
- All internal links resolve (no dead href targets)
- Autocomplete data (if embedded) reflects rebuilt catalog

**Step 1: Check the website for .v1 references**

```bash
grep -n "\.v[0-9]" web/index.html web/blog/*.html | head -20
```
Expected: zero matches.

**Step 2: Check entity count matches catalog**

```bash
python -c "
import json
catalog = json.load(open('sdk/python/pyhall/taxonomy/catalog.json'))
count = catalog['_meta']['total_entities']
print(f'Catalog count: {count}')
# Check web/index.html for the count
import subprocess
result = subprocess.run(['grep', '-o', '[0-9]* entities', 'web/index.html'], capture_output=True, text=True)
print('Web references:', result.stdout.strip())
"
```
Expected: counts match.

**Step 3: Create web QC worker**

Create `tools/qc/web_validator.py`:

```python
"""cap.qc.web.validate — Validate pyhall.dev website against rebuilt catalog."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
V1_RE = re.compile(r'\b[a-z]+\.[a-z]+\.[a-z]+\.v\d+\b')
BRAND_COLOR = "#0050D4"

def run(ctx, request):
    findings = []
    catalog = json.loads((ROOT / "sdk/python/pyhall/taxonomy/catalog.json").read_text())
    expected_count = catalog["_meta"]["total_entities"]
    valid_ids = {e["id"] for e in catalog["entities"]}

    for web_file in [ROOT / "web/index.html", ROOT / "web/blog/the-governance-gap.html"]:
        if not web_file.exists():
            findings.append({"severity": "warning", "file": str(web_file), "detail": "file not found"})
            continue
        content = web_file.read_text()

        # Check for .v1 violations
        for match in V1_RE.finditer(content):
            findings.append({"severity": "error", "file": web_file.name,
                              "detail": f".v1 ID in web: {match.group()}"})

        # Check branding
        if web_file.name == "index.html" and BRAND_COLOR not in content:
            findings.append({"severity": "warning", "file": web_file.name,
                              "detail": f"brand color {BRAND_COLOR} not found"})

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "expected_entity_count": expected_count,
        "findings": findings,
    }
```

**Step 4: Commit**

```bash
git add tools/qc/web_validator.py
git commit -m "feat(qc): pyhall.dev website validator worker"
```

---

## Task 10: QA/QC — Web Playground

**Files:**
- Create: `tools/qc/playground_validator.py`
- Scope: `web/playground/`, `web/playground/js/wcp-engine.js`, `web/playground/data/catalog.json`

**What gets checked:**
- Playground catalog.json matches the rebuilt catalog (same entity count, no `.v1`)
- Blast threshold in `wcp-engine.js` is documented (currently 50, SDK default is 85 — intentional for demo, must be noted)
- Three presets reference valid capability IDs from catalog
- Autocomplete list reflects catalog entity IDs

**Step 1: Verify playground catalog is in sync**

```bash
python -c "
import json
sdk_cat = json.load(open('sdk/python/pyhall/taxonomy/catalog.json'))
web_cat = json.load(open('web/playground/data/catalog.json'))
sdk_ids = {e['id'] for e in sdk_cat['entities']}
web_ids = {e['id'] for e in web_cat['entities']}
diff = sdk_ids.symmetric_difference(web_ids)
print('Differences:', len(diff))
for d in sorted(diff): print(' ', d)
"
```
Expected: 0 differences (build_catalog.py syncs all locations).

**Step 2: Check blast threshold discrepancy**

```bash
grep -n "blast.*threshold\|threshold.*blast\|BLAST_THRESHOLD\|blastThreshold" web/playground/js/wcp-engine.js
```
Document the value. If it's 50 and SDK uses 85, add a comment to wcp-engine.js:
```javascript
// NOTE: Demo threshold intentionally set to 50 (SDK default: 85) for playground visibility
const BLAST_THRESHOLD = 50;
```

**Step 3: Verify preset capability IDs exist in catalog**

```bash
python -c "
import json
catalog = json.load(open('sdk/python/pyhall/taxonomy/catalog.json'))
valid = {e['id'] for e in catalog['entities']}
# Check presets in wcp-engine.js
import re
engine = open('web/playground/js/wcp-engine.js').read()
cap_ids = re.findall(r'cap\.[a-z0-9.\-]+', engine)
for cap in set(cap_ids):
    status = 'OK' if cap in valid else 'MISSING'
    print(f'{status}: {cap}')
"
```
Expected: all capability IDs in presets exist in the catalog.

**Step 4: Create playground QC worker**

Create `tools/qc/playground_validator.py`:

```python
"""cap.qc.playground.validate — Validate web playground against rebuilt catalog."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

def run(ctx, request):
    findings = []
    sdk_catalog = json.loads((ROOT / "sdk/python/pyhall/taxonomy/catalog.json").read_text())
    valid_ids = {e["id"] for e in sdk_catalog["entities"]}

    # Check playground catalog in sync
    pg_catalog_path = ROOT / "web/playground/data/catalog.json"
    if pg_catalog_path.exists():
        pg_catalog = json.loads(pg_catalog_path.read_text())
        pg_ids = {e["id"] for e in pg_catalog.get("entities", [])}
        for missing in valid_ids - pg_ids:
            findings.append({"severity": "error", "detail": f"entity missing from playground catalog: {missing}"})
        for extra in pg_ids - valid_ids:
            findings.append({"severity": "error", "detail": f"stale entity in playground catalog: {extra}"})
    else:
        findings.append({"severity": "error", "detail": "web/playground/data/catalog.json not found"})

    # Check capability IDs in engine
    engine_path = ROOT / "web/playground/js/wcp-engine.js"
    if engine_path.exists():
        engine = engine_path.read_text()
        cap_ids = set(re.findall(r'cap\.[a-z0-9.\-]+', engine))
        for cap in cap_ids:
            if cap not in valid_ids:
                findings.append({"severity": "error", "detail": f"capability ID in wcp-engine.js not in catalog: {cap}"})

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "findings": findings,
    }
```

**Step 5: Commit**

```bash
git add tools/qc/playground_validator.py
git commit -m "feat(qc): web playground validator worker"
```

---

## Task 11: QA/QC — Desktop App

**Files:**
- Create: `tools/qc/desktop_validator.py`
- Scope: `apps/desktop/src/js/api.js`, `apps/desktop/src-tauri/src/lib.rs`

**What gets checked:**
- `enroll_worker` Tauri command accepts registry records with the new 14-field schema
- `validate_registry_record` command rejects entity IDs containing `.v1`
- Six screens load without referencing stale entity IDs
- API endpoint paths match what the desktop app expects (`/wcp/capabilities`, `/wcp/workers`, `/wcp/health`)

**Step 1: Check desktop JS for .v1 references**

```bash
grep -rn "\.v[0-9]" apps/desktop/src/js/ apps/desktop/src-tauri/src/
```
Expected: zero matches.

**Step 2: Check API endpoint paths**

```bash
grep -n "fetch\|axios\|request" apps/desktop/src/js/api.js | grep -v "//\s" | head -20
```
Verify endpoints match WCP spec §5.6: `/wcp/capabilities`, `/wcp/workers`, `/wcp/health`.

**Step 3: Create desktop QC worker**

Create `tools/qc/desktop_validator.py`:

```python
"""cap.qc.desktop.validate — Validate desktop app against current spec."""
import re
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
V1_RE = re.compile(r'\b[a-z]+\.[a-z]+\.[a-z]+\.v\d+\b')
REQUIRED_ENDPOINTS = ["/wcp/capabilities", "/wcp/workers", "/wcp/health"]

def run(ctx, request):
    findings = []

    api_js = ROOT / "apps/desktop/src/js/api.js"
    if api_js.exists():
        content = api_js.read_text()
        for match in V1_RE.finditer(content):
            findings.append({"severity": "error", "file": "api.js",
                              "detail": f".v1 reference: {match.group()}"})
        for endpoint in REQUIRED_ENDPOINTS:
            if endpoint not in content:
                findings.append({"severity": "warning", "file": "api.js",
                                  "detail": f"expected endpoint not found: {endpoint}"})
    else:
        findings.append({"severity": "error", "detail": "apps/desktop/src/js/api.js not found"})

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "findings": findings,
    }
```

**Step 4: Commit**

```bash
git add tools/qc/desktop_validator.py
git commit -m "feat(qc): desktop app validator worker"
```

---

## Task 12: QA/QC — Research Docs + Evidence Catalog

**Files:**
- Create: `tools/qc/docs_validator.py`
- Scope: `docs/research/`, `docs/security/`, `WCP_SPEC.md`

**What gets checked:**
- All WCP entity IDs referenced in any doc exist in the rebuilt catalog
- No `.v1` in any doc that will be published (WCP_SPEC.md, research docs, blog)
- Evidence catalog stats are present (the 30 citable stats in `WCP_EVIDENCE_CATALOG_2026-02-26.md`)
- WCP_SPEC.md version header matches v0.1-DRAFT
- No broken cross-references between docs

**Step 1: Scan all docs for .v1 references**

```bash
grep -rn "\.v[0-9]" docs/ WCP_SPEC.md --include="*.md" | grep -v "^Binary\|\.git"
```
Expected: zero matches in any doc that will be published.

**Step 2: Verify evidence catalog is present and has citable stats**

```bash
python -c "
from pathlib import Path
ec = Path('docs/research/WCP_EVIDENCE_CATALOG_2026-02-26.md')
if not ec.exists():
    print('MISSING: evidence catalog')
else:
    content = ec.read_text()
    print(f'Evidence catalog: {len(content.split(chr(10)))} lines')
    # Count percentage/stat mentions
    import re
    stats = re.findall(r'\d+[%\$]|\d+\.\d+%', content)
    print(f'Citable stats found: {len(stats)}')
"
```
Expected: 844 lines, 30+ citable stats.

**Step 3: Create docs QC worker**

Create `tools/qc/docs_validator.py`:

```python
"""cap.qc.docs.validate — Validate research docs and WCP_SPEC against catalog."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
V1_RE = re.compile(r'\b(?:cap|wrk|ctrl|prof|evt)\.[a-z0-9.\-]+\.v\d+\b')
ENTITY_ID_RE = re.compile(r'\b(?:cap|wrk|ctrl|prof|evt)\.[a-z0-9.\-]{3,}\b')

PUBLISHED_DOCS = [
    "WCP_SPEC.md",
    "docs/research/WCP_EVIDENCE_CATALOG_2026-02-26.md",
    "docs/research/WCP_MARKET_VALIDATION_2026-02-26.md",
    "web/blog/the-governance-gap.html",
]

def run(ctx, request):
    findings = []
    catalog = json.loads((ROOT / "sdk/python/pyhall/taxonomy/catalog.json").read_text())
    valid_ids = {e["id"] for e in catalog["entities"]}

    for doc_rel in PUBLISHED_DOCS:
        doc = ROOT / doc_rel
        if not doc.exists():
            findings.append({"severity": "warning", "file": doc_rel, "detail": "file not found"})
            continue
        content = doc.read_text()

        # .v1 check
        for match in V1_RE.finditer(content):
            findings.append({"severity": "error", "file": doc_rel,
                              "detail": f".v1 entity ID in published doc: {match.group()}"})

        # Reference check — entity IDs mentioned must exist in catalog
        for match in ENTITY_ID_RE.finditer(content):
            eid = match.group()
            if eid not in valid_ids and len(eid.split(".")) >= 3:
                findings.append({"severity": "warning", "file": doc_rel,
                                  "detail": f"entity ID not in catalog: {eid}"})

    return {
        "passed": not any(f["severity"] == "error" for f in findings),
        "findings": findings,
    }
```

**Step 4: Commit**

```bash
git add tools/qc/docs_validator.py
git commit -m "feat(qc): research docs and evidence catalog validator worker"
```

---

## Task 13: Archive Workforce-OS + Stale Files

**Step 1: Archive workforce-os**

```bash
mkdir -p /mnt/fafolab/dev/pyhall/archive/2026-02-26
mv /mnt/fafolab/dev/pyhall/lab/workforce-os /mnt/fafolab/dev/pyhall/archive/2026-02-26/workforce-os
```

**Step 2: Commit the archive to the private repo**

```bash
cd /mnt/fafolab/dev/pyhall
git add archive/2026-02-26/ lab/
git commit -m "chore: archive workforce-os (predates v0.1 security rounds)"
```

**Step 3: Run stale_scanner and review candidates**

```bash
cd /mnt/fafolab/dev/pyhall/git
python -c "
from tools.qc.stale_scanner import run
result = run({}, {})
for c in result['archive_candidates']:
    print(c['path'], '->', c['reason'])
"
```
Review output. For each confirmed stale file, move to `archive/2026-02-26/`.

---

## Task 16: Reasoning Agent — Implementation Review

**When:** After Tasks 1-3 (TypeScript + Go attestation complete)
**Agent type:** `feature-dev:code-reviewer` subagent
**Output:** `release/qa-reports/review-attestation-impl.md`

**What the agent reviews:**

Dispatch a code-reviewer subagent with this scope:

> Read the Python attestation implementation (the reference) in `sdk/python/pyhall/registry.py` and `sdk/python/pyhall/router.py`. Then read the TypeScript implementation in `sdk/typescript/src/registry.ts` and `sdk/typescript/src/router.ts`. Then read the Go implementation in `sdk/go/wcp/registry.go` and `sdk/go/wcp/router.go`.
>
> For each of the three implementations, reason about:
> 1. Does it correctly implement WCP spec §5.10 (worker code attestation)?
> 2. Does it match the Python reference behavior exactly?
> 3. Are there edge cases not handled? (symlinks, empty files, concurrent modification, missing files after registration)
> 4. Are the deny codes consistent across all three? (`DENY_WORKER_TAMPERED`, `DENY_ATTESTATION_UNCONFIGURED`)
> 5. Does the evidence receipt include all required fields? (`worker_attestation_checked`, `worker_attestation_valid`, `registered_hash`, `current_hash`)
> 6. Are the tests (CV-013 in all three SDKs) actually testing the right behavior?
>
> Report: confidence-rated findings only. High confidence issues are blockers. Medium confidence are warnings. Write to `release/qa-reports/review-attestation-impl.md`.

**Gate:** No HIGH confidence findings before proceeding to Task 14.

---

## Task 17: Reasoning Agent — Worker Correctness Review

**When:** After Tasks 7-12 (all QC workers built)
**Agent type:** `feature-dev:code-reviewer` subagent
**Output:** `release/qa-reports/review-worker-correctness.md`

**What the agent reviews:**

Dispatch a code-reviewer subagent with this scope:

> Read every QC worker in `tools/qc/`. For each worker, reason about:
> 1. Does the worker actually check what its description says it checks?
> 2. Is the check correct? (e.g., does `catalog_validator.py` correctly implement spec §3.2/§3.4 ID rules?)
> 3. Are there false negatives — cases where a real problem would pass undetected?
> 4. Are there false positives — cases where valid content would be flagged as an error?
> 5. Is the `passed` return value meaningful? Does a PASS from this worker actually mean what the release checklist assumes it means?
> 6. Does each worker write findings in a consistent format usable by the release gate?
>
> For each worker: APPROVE (logic is correct), WARN (logic has gaps but acceptable), or BLOCK (logic is wrong — this worker should not be trusted in the release gate).
>
> Write findings to `release/qa-reports/review-worker-correctness.md`.

**Gate:** No BLOCK findings before running the release gate (Task 15).

---

## Task 18: Reasoning Agent — System Coherence Review

**When:** After Task 13 (archive complete, all code in place)
**Agent type:** `feature-dev:code-explorer` subagent
**Output:** `release/qa-reports/review-system-coherence.md`

**What the agent reviews:**

Dispatch a code-explorer subagent with this scope:

> Read the following in full: `WCP_SPEC.md`, the Python SDK (`sdk/python/pyhall/`), one routing rule from each language, the catalog (`sdk/python/pyhall/taxonomy/catalog.json`), and the web playground (`web/playground/js/wcp-engine.js`).
>
> Reason about the system as a whole:
> 1. Does the spec match the implementation? Pick 5 specific spec requirements and verify each SDK implements them.
> 2. Does the catalog make sense as a taxonomy? Are the entity types (capability, worker, control, profile, event) used consistently?
> 3. Does the playground reflect the SDK behavior? (blast thresholds, deny codes, routing logic)
> 4. Are the three CLIs consistent with each other? Do they expose the same capabilities?
> 5. Is the desktop app's API layer aligned with the WCP discovery API (§5.6)?
> 6. Is there anything in the release that contradicts the spec, creates confusion, or would embarrass the project publicly?
>
> This is the "does it hang together" review. Be honest. Write findings to `release/qa-reports/review-system-coherence.md`.

**Gate:** Reviewer must explicitly state "SYSTEM COHERENT: ready for public release" or list blocking issues.

---

## Task 19: Reasoning Agent — Research + Narrative Review

**When:** After Task 14 (Round 9 security testing complete)
**Agent type:** `feature-dev:code-reviewer` subagent (reading docs, not code)
**Output:** `release/qa-reports/review-research-narrative.md`

**What the agent reviews:**

Dispatch a subagent with this scope:

> Read the following documents in full: `docs/research/WCP_EVIDENCE_CATALOG_2026-02-26.md`, `docs/research/WCP_MARKET_VALIDATION_2026-02-26.md`, `web/blog/the-governance-gap.html`, and `WCP_SPEC.md`.
>
> Reason about the research and narrative:
> 1. Are the statistics accurate and properly attributed? (e.g., "87% of agents lack safety cards" — is the source cited? Is it used in the right context?)
> 2. Are entity IDs referenced in the blog and docs real catalog entries?
> 3. Does the narrative (governance gap, NIST alignment, WCP as the answer) hold up to scrutiny? Would a skeptical reviewer at NIST find the claims credible?
> 4. Is the NIST alignment argument supported by actual spec text? (NIST Pillar 2 calling for "community-led open-source protocol development" — does WCP actually satisfy this?)
> 5. Are there any claims that are unsubstantiated, misleading, or that could undermine credibility in a public comment?
> 6. Is the Round 9 security report complete and honest? Does it accurately document the limitations of v0.1 attestation?
>
> Write findings to `release/qa-reports/review-research-narrative.md`. Flag anything that would embarrass the project in the NIST comment process.

**Gate:** Reviewer must confirm research is credible and NIST-ready, or flag specific items for correction.

---

## Task 14: Round 9 Security Testing

**File:** `release/qa-reports/round-9-attestation.md`

Run all 7 attacks manually and document results. Each attack follows the pattern: set up the attack, run a dispatch, verify the correct DENY code fires.

**R1 — Hash substitution (registry write access)**
```python
# Register worker, then update the registry hash to match a malicious file
reg.register_attestation("wrk.test.cv013", str(malicious_file))  # overwrite hash
# Dispatch → should PASS (hash now matches malicious). This is the threat model —
# attestation stops unauthorized modification, not insider attacks.
# Document: defense is signatory validation + audit trail, not hash alone.
```

**R2 — Race condition window**
```python
# Register with clean file, begin dispatch, mutate between registration and dispatch
# With synchronous hash check at dispatch time, race window is eliminated.
# Verify: hash check happens at dispatch, not at enrollment.
```

**R3 — Path traversal**
```python
# Attempt to register with a path like "../../malicious.py"
hash = reg.register_attestation("wrk.test", "../../malicious.py")
# Verify: file is resolved to absolute path. Traversal doesn't affect hash — whatever
# file is at that resolved path gets hashed. Document the behavior.
```

**R4 — Symlink swap**
```python
link = tmp / "worker_link.py"
link.symlink_to(clean_file)
reg.register_attestation("wrk.test", str(link))
link.unlink()
link.symlink_to(malicious_file)  # swap target
# Dispatch → verify DENY_WORKER_TAMPERED (hash now mismatches)
```

**R5 — Encoding variant**
```python
# UTF-8 vs latin-1 for same content
# Hash is of raw bytes — encoding differences produce different hashes
# Document: developers must use consistent encoding; Python readFileSync reads raw bytes.
```

**R6 — Registry poisoning via direct dict access**
```python
# Attempt: reg._attestation_hashes["wrk.test"] = malicious_hash
# Python: this succeeds (name mangling doesn't prevent it in tests)
# Document: registry is in-memory — physical security of the host is the outer defense.
# The audit trail in pyhall_audit.db shows when registry was modified.
```

**R7 — Ban list bypass**
```python
# Register clean hash. No ban list implemented locally in v0.1.
# Document: pyhall.dev ban list is v0.2. In v0.1, hash check only validates against
# registered hash — not against a global ban list. Limitation documented in spec.
```

Write findings to `release/qa-reports/round-9-attestation.md`.

---

## Task 15: Release Gate

**Step 1: Run the release gate worker**

```bash
cd /mnt/fafolab/dev/pyhall/git
python -c "
from tools.qc.release_gate import run
result = run({}, {})
print('Release gate:', 'PASS' if result['passed'] else 'FAIL')
print('Report:', result['report_path'])
"
```

**Step 2: Check the RELEASING.md checklist**

Open `RELEASING.md` (create it if not present) and verify all items:

```markdown
# PyHall v0.1.0 Release Checklist

## SDK + Core Protocol
- [ ] CV-013 passes in Python, TypeScript, Go
- [ ] CV-001 through CV-012 still pass in all three SDKs
- [ ] Python SDK: 105+ tests pass
- [ ] TypeScript SDK: 83+ tests pass
- [ ] Go SDK: all tests pass
- [ ] Catalog rebuilt — zero .v1 violations, zero schema violations

## CLI Apps
- [ ] Python CLI: 105 tests pass, no .v1 in any output
- [ ] TypeScript CLI: 36 tests pass, no .v1 in any output
- [ ] Go CLI: 5 tests pass, no .v1 in any output
- [ ] All 3 CLIs: version, search, explain, browse, scaffold all work against rebuilt catalog

## Web Apps
- [ ] pyhall.dev site: no .v1 references, entity count matches catalog, #0050D4 branding present
- [ ] Web playground: catalog in sync, preset capability IDs valid, blast threshold documented
- [ ] Blog post: no .v1 references, all entity IDs valid

## Desktop App
- [ ] Desktop app: no .v1 references in api.js, WCP endpoints correct
- [ ] enroll_worker Tauri command accepts new 14-field schema

## Research + Docs
- [ ] WCP_SPEC.md: no .v1 in spec text, version header = 0.1-DRAFT
- [ ] Evidence catalog (844 lines, 30+ citable stats) present
- [ ] Market validation doc present
- [ ] Security findings: Round 9 report complete, 7 attacks documented

## Reasoning Agent Reviews
- [ ] Agent 1 (Implementation): no HIGH findings on TypeScript + Go attestation
- [ ] Agent 2 (Worker Correctness): no BLOCK findings on any QC worker
- [ ] Agent 3 (System Coherence): explicit "SYSTEM COHERENT" sign-off
- [ ] Agent 4 (Research + Narrative): confirms research is credible and NIST-ready

## Audit + QA
- [ ] QC worker fleet: all 10 workers run clean (5 core + 5 app/doc)
- [ ] release_gate.py: all three SDK test suites green
- [ ] pyhall_audit.db hash chain intact
- [ ] workforce-os archived

## Release
- [ ] CHANGELOG.md updated with v0.1.0 attestation features
- [ ] RELEASING.md complete
- [ ] git tag v0.1.0 created in git/
- [ ] Push to fafolab/pyhall (public repo)
- [ ] PyPI: pip install pyhall
- [ ] npm: @pyhall/core + @pyhall/cli
- [ ] Cloudflare Pages: pyhall.dev deployed
```

**Step 3: When all checks pass — tag and push**

```bash
cd /mnt/fafolab/dev/pyhall/git
git tag v0.1.0 -m "PyHall v0.1.0 — Worker Class Protocol reference implementation"
gh repo create fafolab/pyhall --public --description "PyHall — Worker Class Protocol SDK"
git remote add public https://github.com/fafolab/pyhall.git
git push public main --tags
```

---

*Plan saved to `docs/plans/2026-02-26-attestation-qaqc-plan.md`*
