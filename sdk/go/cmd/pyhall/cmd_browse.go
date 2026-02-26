package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newBrowseCmd() *cobra.Command {
	var packFlag string
	var typeFlag string

	cmd := &cobra.Command{
		Use:   "browse",
		Short: "Browse the WCP taxonomy catalog",
		Long: `Browse the WCP taxonomy catalog with optional filters.

Filter by pack:   pyhall browse --pack pack.01
Filter by type:   pyhall browse --type cap
Combine filters:  pyhall browse --pack pack.10 --type cap

Valid types: cap, wrk, ctrl, pol, prof`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loadCatalog()
			if err != nil {
				return err
			}

			// Normalize type flag to full type name
			entityType := normalizeType(typeFlag)

			// If no filters, show pack list
			if packFlag == "" && entityType == "" {
				return browsePacks(c)
			}

			entities := c.Browse(packFlag, entityType)
			if len(entities) == 0 {
				msg := "No entities found"
				if packFlag != "" {
					msg += fmt.Sprintf(" in pack %q", packFlag)
				}
				if entityType != "" {
					msg += fmt.Sprintf(" with type %q", typeFlag)
				}
				fmt.Println(warningOrange.Render(msg))
				return nil
			}

			// Print header
			header := "Browse"
			if packFlag != "" {
				if p, err2 := c.PackByID(packFlag); err2 == nil {
					header += fmt.Sprintf(" — %s (%s)", p.Name, packFlag)
				} else {
					header += " — " + packFlag
				}
			}
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

	cmd.Flags().StringVar(&packFlag, "pack", "", "Filter by pack ID (e.g. pack.01)")
	cmd.Flags().StringVar(&typeFlag, "type", "", "Filter by entity type: cap, wrk, ctrl, pol, prof")
	return cmd
}

func browsePacks(c *Catalog) error {
	fmt.Printf("\n  %s\n\n", headerStyle.Render("WCP Taxonomy Packs"))
	fmt.Printf("  %-12s  %-5s  %s\n",
		dimStyle.Render("Pack ID"),
		dimStyle.Render("Count"),
		dimStyle.Render("Name"),
	)
	fmt.Printf("  %s\n", dimStyle.Render(strings.Repeat("─", 60)))

	for _, p := range c.Packs {
		countStr := fmt.Sprintf("%d", p.EntityCount)
		if p.EntityCount == 0 {
			countStr = dimStyle.Render("0")
		} else {
			countStr = primaryBlue.Render(countStr)
		}
		fmt.Printf("  %-12s  %-5s  %s\n",
			lightBlue.Render(p.ID),
			countStr,
			p.Name,
		)
	}

	fmt.Printf("\n  %s\n", dimStyle.Render(
		fmt.Sprintf("Total: %d packs, %d entities. Use --pack <id> to filter.", c.PackCount(), c.EntityCount()),
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
