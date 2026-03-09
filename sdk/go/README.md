# pyhall-go — WCP Worker Class Protocol (Go)

**Status:** v0.3.0 — routing, registry client, and full package attestation implemented.
**Spec:** [WCP_SPEC.md](https://github.com/workerclassprotocol/wcp/blob/main/WCP_SPEC.md)
**Production implementation:** [pip install pyhall-wcp](https://github.com/pyhall/pyhall-python)

---

## What this is

This is the Go implementation of [WCP — Worker Class Protocol](https://github.com/workerclassprotocol/wcp/blob/main/WCP_SPEC.md), an open standard for governing worker dispatch in AI agent systems.

The Python reference implementation (`pyhall`) is the production-ready version. This Go package mirrors its type system and routing interfaces so Go services can participate in a WCP-governed worker fleet.

**If you need production routing or package attestation today:** use PyHall.

```bash
pip install pyhall-wcp==0.3.0
pyhall route --capability cap.doc.summarize --env dev --data-label INTERNAL
```

This Go package is for teams that need to write WCP workers or consume WCP routing decisions from a Go service.

---

## Module

```
github.com/pyhall/pyhall-go
```

Go 1.22+. Zero external runtime dependencies — stdlib only.

---

## Package Layout

```
wcp/
  models.go           — RouteInput, RouteDecision, supporting types
  router.go           — MakeDecision() — the primary routing entrypoint (stub)
  registry.go         — Registry — in-memory worker enrollment store
  registry_client.go  — RegistryClient — HTTP client for api.pyhall.dev
  policy_gate.go      — PolicyGate interface + DefaultPolicyGate stub
  common.go           — NowUTC(), SHA256Hex(), OK/Err helpers

workers/examples/hello_worker/
  worker.go             — minimal canonical worker implementation
  registry_record.json  — enrollment record for the hello worker
```

---

## Quick Start — Routing

```go
import (
    "fmt"
    "github.com/pyhall/pyhall-go/wcp"
)

func main() {
    registry := wcp.NewRegistry()

    // Enroll a worker
    err := registry.Enroll(wcp.WorkerRegistryRecord{
        WorkerID:        "org.example.my-summarizer",
        WorkerSpeciesID: "wrk.doc.summarizer",
        Capabilities:    []string{"cap.doc.summarize"},
        RiskTier:        "low",
    })
    if err != nil {
        panic(err)
    }

    // Route a capability request
    input := wcp.RouteInput{
        CapabilityID:  "cap.doc.summarize",
        Env:           wcp.EnvDev,
        DataLabel:     wcp.DataLabelInternal,
        TenantRisk:    wcp.TenantRiskLow,
        QoSClass:      wcp.QoSP2,
        TenantID:      "tenant-001",
        CorrelationID: "550e8400-e29b-41d4-a716-446655440000",
        Request:       map[string]any{"text": "Summarize this document..."},
    }

    decision := wcp.MakeDecision(input, registry, wcp.RouterOptions{})

    if decision.Denied {
        fmt.Println("Denied:", decision.DenyReasonIfDenied)
    } else {
        fmt.Println("Route to:", *decision.SelectedWorkerSpeciesID)
    }
}
```

---

## Registry Client

Go has parity with Python and TypeScript for the `api.pyhall.dev` HTTP API.

```go
import "github.com/pyhall/pyhall-go/wcp"

client := wcp.NewRegistryClient(wcp.RegistryClientOptions{
    // BaseURL defaults to "https://api.pyhall.dev"
    // SessionToken: "your-session-jwt",
    // Timeout: 10 * time.Second,
    // CacheTTL: 60 * time.Second,
})

// Verify a worker's attestation status
resp, err := client.Verify("org.example.my-worker")
if err != nil {
    log.Fatal(err)
}
fmt.Println(resp.Status)       // "active" | "revoked" | "banned" | "unknown"
fmt.Println(resp.AIGenerated)  // bool — was this package AI-assisted?

// Check the ban-list
banned, err := client.IsHashBanned(someHash)

// Fetch all confirmed ban-list entries
entries, err := client.GetBanList(500)

// Registry health check
h, err := client.Health()

// Pre-populate cache before routing
err = client.Prefetch([]string{"org.example.worker-a", "org.example.worker-b"})

// Synchronous hash lookup (uses cache populated by Prefetch)
hash, ok := client.GetWorkerHash("org.example.worker-a")
```

`VerifyResponse` fields: `WorkerID`, `Status`, `CurrentHash`, `Banned`,
`BanReason`, `AttestedAt`, `AIGenerated`, `AIService`, `AIModel`,
`AISessionFingerprint`.

Override the registry URL via `RegistryClientOptions.BaseURL` or set the
`PYHALL_REGISTRY_URL` environment variable.

---

## Package Attestation

Full-package attestation is fully implemented in v0.3.0:

```go
import "github.com/pyhall/pyhall-go/wcp"

// Build + sign a manifest at CI/deploy time
manifest, err := wcp.BuildManifest(wcp.BuildManifestOptions{
    PackageRoot:     "/opt/workers/my-worker",
    WorkerID:        "org.example.my-worker.i-1",
    WorkerSpeciesID: "wrk.example.my-worker",
    WorkerVersion:   "1.0.0",
    SigningSecret:   os.Getenv("WCP_ATTEST_HMAC_KEY"),
})
wcp.WriteManifest(manifest, "/opt/workers/my-worker/manifest.json")

// Verify at runtime (fail-closed)
v := &wcp.PackageAttestationVerifier{
    PackageRoot:     "/opt/workers/my-worker",
    ManifestPath:    "/opt/workers/my-worker/manifest.json",
    WorkerID:        "org.example.my-worker.i-1",
    WorkerSpeciesID: "wrk.example.my-worker",
}
result := v.Verify()
if !result.OK {
    log.Fatalf("Attestation denied: %s", result.DenyCode)
}
```

---

## WCP Compliance Level

| Requirement | Status |
|-------------|--------|
| Capability routing | Stub (workers enrolled via Registry) |
| Fail-closed (unknown capability = deny) | Done |
| Deterministic routing | Done |
| Controls enforcement | TODO |
| Mandatory telemetry | Done (three events emitted) |
| Dry-run support | Done |
| Blast radius scoring | TODO |
| Policy gate | Stub (DefaultPolicyGate passes through) |
| Evidence receipts | Done (in hello_worker example) |
| Discovery API | TODO |
| Registry client (api.pyhall.dev) | Done |
| Package attestation | Not yet ported |

Full WCP-Standard and WCP-Full compliance requires completing the TODOs in
`router.go` and `policy_gate.go`.

---

## What is WCP?

WCP (Worker Class Protocol) defines the governance layer between a capability request and its execution. It answers: *should this worker be trusted with this job, under these conditions, with this data?*

Every protocol in the agent ecosystem — MCP, A2A, ACP — defines how agents communicate. None define whether a worker should be trusted to execute. WCP fills that gap.

```
Agent reasoning
      |
WCP Hall (capability request → governed routing → dispatch)
      |
Transport (MCP, HTTP, A2A, subprocess)
      |
Worker execution
```

Read the full spec: [WCP_SPEC.md](https://github.com/workerclassprotocol/wcp/blob/main/WCP_SPEC.md)

---

## License

Apache 2.0. See [LICENSE](LICENSE).
