# PyHall v0.1 Attestation + QA/QC Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship worker attestation (WCP §5.10) in all three SDKs, with a QA/QC worker fleet, catalog rebuild, and Round 9 adversarial security testing — all gated through a release checklist by March 1, 2026.

**Architecture:** Python attestation is the reference (complete). TypeScript and Go implement the same pattern: `registerAttestation()` computes SHA-256 of worker source file at enrollment; router checks current hash at dispatch; mismatch → deny. Five QA/QC workers (Python, v0.1 architecture) enforce spec compliance and gate the release. Catalog is rebuilt from a Python source-of-truth generator validated against WCP spec §3.2/§3.4.

**Tech Stack:** Python 3.12, TypeScript (Node crypto), Go 1.21 (crypto/sha256), pytest, Vitest, Go testing, SQLite

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

## Task 8: Archive Workforce-OS + Stale Files

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

## Task 9: Round 9 Security Testing

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

## Task 10: Release Gate

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

- [ ] CV-013 passes in Python, TypeScript, Go
- [ ] CV-001 through CV-012 still pass in all three SDKs
- [ ] QC worker fleet: catalog_validator PASS, stale_scanner reviewed
- [ ] release_gate.py: all three SDK test suites green
- [ ] Catalog rebuilt — zero .v1 violations, zero schema violations
- [ ] Round 9 security report complete (7 attacks documented)
- [ ] pyhall_audit.db hash chain intact
- [ ] workforce-os archived
- [ ] CHANGELOG.md updated
- [ ] git tag v0.1.0 created in git/
- [ ] Push to fafolab/pyhall (public repo)
- [ ] PyPI: pip install pyhall
- [ ] npm: npm install @pyhall/core
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
