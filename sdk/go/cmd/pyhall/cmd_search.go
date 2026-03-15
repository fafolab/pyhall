package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newSearchCmd() *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Fuzzy-search the WCP taxonomy catalog",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]

			c, err := loadCatalog()
			if err != nil {
				return err
			}

			results := c.Search(query)
			if len(results) == 0 {
				fmt.Printf("%s No results for %q\n", warningOrange.Render("!"), query)
				return nil
			}

			if limit > 0 && len(results) > limit {
				results = results[:limit]
			}

			fmt.Printf("%s  Showing %s results for %q\n\n",
				headerStyle.Render("Search"),
				primaryBlue.Render(fmt.Sprintf("%d", len(results))),
				query,
			)

			for _, r := range results {
				typeLabel := entityTypeLabel(r.Entity.Type)
				scoreStr := dimStyle.Render(fmt.Sprintf("score:%d", r.Score))
				fmt.Printf("  %s  %s  %s\n",
					primaryBlue.Render(r.Entity.ID),
					lightBlue.Render(typeLabel),
					scoreStr,
				)
				fmt.Printf("  %s\n", r.Entity.Name)
				if r.Entity.Description != "" {
					desc := r.Entity.Description
					if len(desc) > 100 {
						desc = desc[:97] + "..."
					}
					fmt.Printf("  %s\n", dimStyle.Render(desc))
				}
				fmt.Println()
			}

			fmt.Printf("%s\n", dimStyle.Render(
				fmt.Sprintf("Run 'pyhall explain <id>' for full details. %d total matches.", len(c.Search(query))),
			))
			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 20, "Maximum number of results to show")
	return cmd
}

func entityTypeLabel(t string) string {
	switch strings.ToLower(t) {
	case "capability":
		return "[cap]"
	case "worker_species":
		return "[wrk]"
	case "control":
		return "[ctrl]"
	case "policy":
		return "[pol]"
	case "profile":
		return "[prof]"
	default:
		return "[" + t + "]"
	}
}
