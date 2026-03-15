package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newBrowseCmd() *cobra.Command {
	var typeFlag string

	cmd := &cobra.Command{
		Use:   "browse",
		Short: "Browse the WCP taxonomy catalog",
		Long: `Browse the WCP taxonomy catalog with optional type filter.

Without flags: show entity counts by type.
Filter by type:   pyhall browse --type cap

Valid types: cap, wrk, ctrl, pol, prof`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loadCatalog()
			if err != nil {
				return err
			}

			// Normalize type flag to full type name
			entityType := normalizeType(typeFlag)

			// If no type filter, show summary by entity type
			if entityType == "" {
				return browseTypes(c)
			}

			entities := c.Browse(entityType)
			if len(entities) == 0 {
				msg := "No entities found"
				if entityType != "" {
					msg += fmt.Sprintf(" with type %q", typeFlag)
				}
				fmt.Println(warningOrange.Render(msg))
				return nil
			}

			// Print header
			header := "Browse"
			if entityType != "" {
				header += " [" + typeFlag + "]"
			}
			fmt.Printf("\n  %s\n\n", headerStyle.Render(header))

			// Group by type for readability
			byType := make(map[string][]Entity)
			typeOrder := []string{}
			for _, e := range entities {
				if _, ok := byType[e.Type]; !ok {
					typeOrder = append(typeOrder, e.Type)
				}
				byType[e.Type] = append(byType[e.Type], e)
			}

			for _, t := range typeOrder {
				group := byType[t]
				fmt.Printf("  %s\n", lightBlue.Render(strings.ToUpper(t)+" ("+fmt.Sprintf("%d", len(group))+")"))
				for _, e := range group {
					fmt.Printf("    %s\n", primaryBlue.Render(e.ID))
					fmt.Printf("    %s\n", e.Name)
					if e.Description != "" {
						desc := e.Description
						if len(desc) > 90 {
							desc = desc[:87] + "..."
						}
						fmt.Printf("    %s\n", dimStyle.Render(desc))
					}
					fmt.Println()
				}
			}

			fmt.Printf("%s\n", dimStyle.Render(fmt.Sprintf(
				"%d entities shown. Run 'pyhall explain <id>' for details.",
				len(entities),
			)))
			return nil
		},
	}

	cmd.Flags().StringVar(&typeFlag, "type", "", "Filter by entity type: cap, wrk, ctrl, pol, prof")
	return cmd
}

func browseTypes(c *Catalog) error {
	counts := make(map[string]int)
	for _, e := range c.Entities {
		counts[e.Type]++
	}

	fmt.Printf("\n  %s\n\n", headerStyle.Render("WCP Taxonomy"))
	fmt.Printf("  %-20s  %-6s  %s\n",
		dimStyle.Render("Type"),
		dimStyle.Render("Short"),
		dimStyle.Render("Count"),
	)
	fmt.Printf("  %s\n", dimStyle.Render(strings.Repeat("─", 40)))

	typeRows := []struct{ full, short string }{
		{"capability", "cap"},
		{"worker_species", "wrk"},
		{"control", "ctrl"},
		{"profile", "prof"},
		{"policy", "pol"},
	}
	for _, tr := range typeRows {
		n := counts[tr.full]
		countStr := dimStyle.Render("—")
		if n > 0 {
			countStr = primaryBlue.Render(fmt.Sprintf("%d", n))
		}
		fmt.Printf("  %-20s  %-6s  %s\n", tr.full, tr.short, countStr)
	}

	fmt.Printf("\n  %s\n", dimStyle.Render(
		fmt.Sprintf("Total: %d entities. Use --type <short> to filter.", c.EntityCount()),
	))
	return nil
}

// normalizeType converts short type flags (cap, wrk, ctrl) to full type names.
func normalizeType(t string) string {
	switch strings.ToLower(t) {
	case "cap", "capability":
		return "capability"
	case "wrk", "worker", "worker_species":
		return "worker_species"
	case "ctrl", "control":
		return "control"
	case "pol", "policy":
		return "policy"
	case "prof", "profile":
		return "profile"
	case "":
		return ""
	default:
		return t
	}
}
