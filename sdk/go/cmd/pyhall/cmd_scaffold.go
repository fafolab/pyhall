package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newScaffoldCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scaffold",
		Short: "Interactive worker scaffold wizard",
		Long: `Scaffold a new WCP worker with pre-filled registry record.

The wizard will:
  1. Ask what the worker does
  2. Search the catalog for matching capabilities
  3. Let you pick a capability ID
  4. Confirm delivery guarantee
  5. Generate worker.go, registry_record.json, and README.md`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScaffold()
		},
	}
}

func runScaffold() error {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println()
	fmt.Println(headerStyle.Render("PyHall Worker Scaffold Wizard"))
	fmt.Println(dimStyle.Render("WCP — Worker Class Protocol | pyhall.dev"))
	fmt.Println()

	// Step 1: What does the worker do?
	fmt.Print(lightBlue.Render("? ") + "What does this worker do? ")
	if !scanner.Scan() {
		return fmt.Errorf("input cancelled")
	}
	description := strings.TrimSpace(scanner.Text())
	if description == "" {
		return fmt.Errorf("description cannot be empty")
	}

	// Step 2: Search catalog for matching capabilities
	c, err := loadCatalog()
	if err != nil {
		return err
	}

	results := c.Search(description)
	// Filter to only capabilities
	var capResults []SearchResult
	for _, r := range results {
		if r.Entity.Type == "capability" {
			capResults = append(capResults, r)
		}
	}
	if len(capResults) > 8 {
		capResults = capResults[:8]
	}

	var selectedCapID string

	if len(capResults) == 0 {
		fmt.Println(warningOrange.Render("  No matching capabilities found in catalog."))
		fmt.Print(lightBlue.Render("? ") + "Enter capability ID manually (e.g. cap.doc.summarize): ")
		if !scanner.Scan() {
			return fmt.Errorf("input cancelled")
		}
		selectedCapID = strings.TrimSpace(scanner.Text())
	} else {
		fmt.Printf("\n  %s\n\n", dimStyle.Render("Matching capabilities:"))
		for i, r := range capResults {
			fmt.Printf("  %s  %s\n      %s\n",
				primaryBlue.Render(fmt.Sprintf("(%d)", i+1)),
				lightBlue.Render(r.Entity.ID),
				r.Entity.Name,
			)
		}
		fmt.Println()
		fmt.Print(lightBlue.Render("? ") + "Select capability (number or type ID directly): ")
		if !scanner.Scan() {
			return fmt.Errorf("input cancelled")
		}
		input := strings.TrimSpace(scanner.Text())

		// Check if numeric selection
		selectedCapID = input
		if len(input) == 1 && input[0] >= '1' && input[0] <= '9' {
			idx := int(input[0]-'1')
			if idx < len(capResults) {
				selectedCapID = capResults[idx].Entity.ID
			}
		}
	}

	if selectedCapID == "" {
		return fmt.Errorf("no capability selected")
	}
	fmt.Printf("  %s capability: %s\n\n", successGreen.Render("Selected"), primaryBlue.Render(selectedCapID))

	// Step 3: Delivery guarantee
	fmt.Printf("  %s\n", dimStyle.Render("Delivery guarantee:"))
	fmt.Printf("  %s best-effort\n", primaryBlue.Render("(1)"))
	fmt.Printf("  %s at-least-once\n", primaryBlue.Render("(2)"))
	fmt.Printf("  %s exactly-once\n", primaryBlue.Render("(3)"))
	fmt.Print(lightBlue.Render("? ") + "Choice [1]: ")
	if !scanner.Scan() {
		return fmt.Errorf("input cancelled")
	}
	guaranteeInput := strings.TrimSpace(scanner.Text())
	if guaranteeInput == "" {
		guaranteeInput = "1"
	}

	guaranteeMap := map[string]string{
		"1": "best-effort",
		"2": "at-least-once",
		"3": "exactly-once",
	}
	guarantee, ok := guaranteeMap[guaranteeInput]
	if !ok {
		guarantee = "best-effort"
	}
	fmt.Printf("  %s guarantee: %s\n\n", successGreen.Render("Selected"), lightBlue.Render(guarantee))

	// Step 4: Output directory
	defaultDir := "./my-worker"
	fmt.Printf(lightBlue.Render("? ")+"Output directory [%s]: ", defaultDir)
	if !scanner.Scan() {
		return fmt.Errorf("input cancelled")
	}
	outDir := strings.TrimSpace(scanner.Text())
	if outDir == "" {
		outDir = defaultDir
	}

	// Create output directory
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", outDir, err)
	}

	// Derive worker species ID from capability ID
	workerSpeciesID := strings.Replace(selectedCapID, "cap.", "wrk.", 1)
	workerID := fmt.Sprintf("org.myorg.%s", strings.ReplaceAll(
		strings.TrimPrefix(workerSpeciesID, "wrk."), ".", "-",
	))

	// Generate files
	if err := writeWorkerGo(outDir, workerSpeciesID, selectedCapID, guarantee); err != nil {
		return err
	}
	if err := writeRegistryRecord(outDir, workerID, workerSpeciesID, selectedCapID, guarantee); err != nil {
		return err
	}
	if err := writeReadme(outDir, workerID, workerSpeciesID, selectedCapID, guarantee, description); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("  %s  Worker scaffolded in %s\n\n", successGreen.Render("Done!"), primaryBlue.Render(outDir))
	fmt.Printf("  %s\n", dimStyle.Render("Files generated:"))
	fmt.Printf("    %s  worker.go\n", successGreen.Render("•"))
	fmt.Printf("    %s  registry_record.json\n", successGreen.Render("•"))
	fmt.Printf("    %s  README.md\n", successGreen.Render("•"))
	fmt.Println()
	fmt.Printf("  %s\n", dimStyle.Render("Next steps:"))
	fmt.Printf("    1. Edit worker.go — implement your Run() logic\n")
	fmt.Printf("    2. Register your worker: submit registry_record.json to your Hall\n")
	fmt.Printf("    3. See pyhall.dev for full WCP documentation\n")
	fmt.Println()

	return nil
}

func writeWorkerGo(outDir, workerSpeciesID, capID, guarantee string) error {
	path := outDir + "/worker.go"

	// Build the generated file as a string directly — no fmt.Sprintf on the
	// template body so that literal %s / %v in the stub are not misinterpreted
	// as format verbs.
	lines := []string{
		"package main",
		"",
		`import (`,
		`	"context"`,
		`	"fmt"`,
		`)`,
		"",
		"// Worker implements the WCP worker species: " + workerSpeciesID,
		"// Capability: " + capID,
		"// Delivery guarantee: " + guarantee,
		"//",
		"// Generated by: pyhall scaffold",
		"// WCP spec: 0.1 | pyhall.dev",
		"",
		"// WorkerContext holds the routing context passed to every worker invocation.",
		"type WorkerContext struct {",
		`	CorrelationID string`,
		`	TenantID      string`,
		`	CapabilityID  string`,
		`	DataLabel     string`,
		`	QoSClass      string`,
		"}",
		"",
		"// Worker is the main worker struct.",
		"type Worker struct{}",
		"",
		"// Run executes the worker logic.",
		"// ctx is the standard Go context (for cancellation/timeout).",
		"// wctx is the WCP WorkerContext (correlation ID, tenant, capability, etc.).",
		"// request is the arbitrary payload from the routing decision.",
		"// Returns a result map and any error.",
		`func (w *Worker) Run(ctx context.Context, wctx WorkerContext, request map[string]any) (map[string]any, error) {`,
		`	// TODO: Implement your worker logic here.`,
		`	//`,
		`	// Required:`,
		`	//   - Propagate wctx.CorrelationID in all downstream calls`,
		`	//   - Record artifact hash if your Hall requires it`,
		`	//   - Return a result map (or error on failure)`,
		`	//`,
		`	// Example:`,
		`	//   input, ok := request["input"].(string)`,
		`	//   if !ok { return nil, fmt.Errorf("missing 'input' field") }`,
		`	//   result := processInput(input)`,
		`	//   return map[string]any{"output": result}, nil`,
		"",
		`	fmt.Printf("[%s] Worker ` + workerSpeciesID + ` invoked for capability %s\n",`,
		`		wctx.CorrelationID, wctx.CapabilityID)`,
		`	return map[string]any{"status": "not_implemented"}, nil`,
		"}",
		"",
		"func main() {",
		`	// Entry point for standalone testing.`,
		`	// In production, workers are dispatched by the WCP Hall.`,
		`	w := &Worker{}`,
		`	result, err := w.Run(`,
		`		context.Background(),`,
		`		WorkerContext{`,
		`			CorrelationID: "00000000-0000-0000-0000-000000000000",`,
		`			TenantID:      "test-tenant",`,
		`			CapabilityID:  "` + capID + `",`,
		`			DataLabel:     "PUBLIC",`,
		`			QoSClass:      "P2",`,
		`		},`,
		`		map[string]any{"input": "hello"},`,
		`	)`,
		`	if err != nil {`,
		`		fmt.Printf("Error: %v\n", err)`,
		`		return`,
		`	}`,
		`	fmt.Printf("Result: %v\n", result)`,
		"}",
		"",
	}

	content := strings.Join(lines, "\n")
	return os.WriteFile(path, []byte(content), 0644)
}

func writeRegistryRecord(outDir, workerID, workerSpeciesID, capID, guarantee string) error {
	path := outDir + "/registry_record.json"

	record := map[string]interface{}{
		"worker_id":         workerID,
		"worker_species_id": workerSpeciesID,
		"capabilities":      []string{capID},
		"risk_tier":         "low",
		"required_controls": []string{},
		"allowed_environments": []string{"dev", "stage", "prod"},
		"delivery_guarantee": guarantee,
		"privilege_envelope": map[string]interface{}{
			"network_egress":    "none",
			"secrets_access":    []string{},
			"filesystem_writes": []string{},
			"tools":             []string{},
		},
		"owner":               "your-org",
		"contact":             "your-email@example.com",
		"notes":               "Generated by pyhall scaffold",
		"catalog_version_min": "0.1.0",
		"registered_at":       time.Now().UTC().Format(time.RFC3339),
		"artifact_hash":       "",
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registry record: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func writeReadme(outDir, workerID, workerSpeciesID, capID, guarantee, description string) error {
	path := outDir + "/README.md"
	content := fmt.Sprintf(`# %s

**WCP Worker Class Protocol** — Generated scaffold

| Field              | Value                   |
|--------------------|-------------------------|
| Worker ID          | `+"`%s`"+`              |
| Worker species     | `+"`%s`"+`              |
| Capability         | `+"`%s`"+`              |
| Delivery guarantee | %s                      |

## Description

%s

## Getting Started

1. Open `+"`worker.go`"+` and implement the `+"`Run()`"+` method.
2. Update `+"`registry_record.json`"+` with your org name, contact, and actual risk tier.
3. Submit `+"`registry_record.json`"+` to your WCP Hall to register the worker.

## WCP Resources

- Specification: [pyhall.dev](https://pyhall.dev)
- WCP spec    — https://github.com/fafolab/wcp
- Python SDK: `+"`pip install pyhall`"+`
- Go SDK: `+"`go get github.com/fafolab/pyhall-go`"+`

## License

Apache 2.0 — FΔFΌ★LΔB
`, workerSpeciesID, workerID, workerSpeciesID, capID, guarantee, description)

	return os.WriteFile(path, []byte(content), 0644)
}
