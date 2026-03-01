# pyhall-go — WCP Worker Class Protocol (Go)

**Status:** v0.1 scaffold — interfaces and stubs only.
**Spec:** [WCP_SPEC.md](https://github.com/fafolab/wcp/blob/main/WCP_SPEC.md)
**Production implementation:** [pip install pyhall](https://github.com/fafolab/pyhall)

---

## What this is

This is the Go scaffolding for [WCP — Worker Class Protocol](https://github.com/fafolab/wcp/blob/main/WCP_SPEC.md), an open standard for governing worker dispatch in AI agent systems.

The Python reference implementation (`pyhall`) is the production-ready version. This Go package mirrors its type system and routing interfaces so Go services can participate in a WCP-governed worker fleet.

**If you need production routing today:** use PyHall.

```bash
pip install pyhall
pyhall route --capability cap.doc.summarize --env dev --data-label INTERNAL
```

This Go package is for teams that need to write WCP workers or consume WCP routing decisions from a Go service.

---

## Package layout

```
wcp/
  models.go       — RouteInput, RouteDecision, supporting types
  router.go       — MakeDecision() — the primary routing entrypoint (stub)
  registry.go     — Registry — in-memory worker enrollment store
  policy_gate.go  — PolicyGate interface + DefaultPolicyGate stub
  common.go       — NowUTC(), SHA256Hex(), OK/Err helpers

workers/examples/hello_worker/
  worker.go             — minimal canonical worker implementation
  registry_record.json  — enrollment record for the hello worker
```

---

## Quick start

```go
import (
    "fmt"
    "github.com/fafolab/pyhall-go/wcp"
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

## WCP compliance level

This scaffold targets **WCP-Basic** compliance:

| Requirement | Status |
|-------------|--------|
| Capability routing | Stub (workers enrolled via Registry) |
| Fail-closed (unknown capability = deny) | Done |
| Deterministic routing | Done (stub rule, deterministic) |
| Controls enforcement | TODO |
| Mandatory telemetry | Done (three events emitted) |
| Dry-run support | Done (no dispatch when DryRun=true) |
| Blast radius scoring | TODO |
| Policy gate | Stub (DefaultPolicyGate passes through) |
| Evidence receipts | Done (in hello_worker example) |
| Discovery API | TODO |

Full WCP-Standard and WCP-Full compliance requires completing the TODOs in `router.go` and `policy_gate.go`.

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

Read the full spec: [WCP_SPEC.md](https://github.com/fafolab/wcp/blob/main/WCP_SPEC.md)

---

## Module

```
github.com/fafolab/pyhall-go
```

Go 1.22+. Zero external runtime dependencies — stdlib only.

---

## License

Apache 2.0. See [LICENSE](LICENSE).
