package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <entity-id>",
		Short: "Show detailed information for a WCP entity by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]

			c, err := loadCatalog()
			if err != nil {
				return err
			}

			e, err := c.FindByID(id)
			if err != nil {
				return fmt.Errorf("%s", errorRed.Render(err.Error()))
			}

			printEntity(e, c)
			return nil
		},
	}
}

func printEntity(e *Entity, c *Catalog) {
	fmt.Println()
	fmt.Printf("  %s\n", headerStyle.Render(e.ID))
	fmt.Printf("  %s\n\n", lightBlue.Render(e.Name))

	row := func(label, value string) {
		if value == "" {
			return
		}
		fmt.Printf("  %-22s %s\n", dimStyle.Render(label+":"), value)
	}

	row("Type", entityTypeLabel(e.Type))
	row("Pack", packLabel(e.PackID, c))

	if e.RiskTier != "" {
		row("Risk tier", riskTierStyled(e.RiskTier))
	}
	if e.Level != "" {
		row("Level", e.Level)
	}
	if e.Guarantee != "" {
		row("Guarantee", e.Guarantee)
	}
	if e.BlastScore > 0 {
		row("Blast score", blastScoreStyled(e.BlastScore))
	}

	if e.Description != "" {
		fmt.Printf("\n  %s\n", dimStyle.Render("Description:"))
		wrapped := wordWrap(e.Description, 72)
		for _, line := range wrapped {
			fmt.Printf("    %s\n", line)
		}
	}

	if len(e.RequiredControls) > 0 {
		fmt.Printf("\n  %s\n", dimStyle.Render("Required controls:"))
		for _, ctrl := range e.RequiredControls {
			fmt.Printf("    %s %s\n", warningOrange.Render("•"), ctrl)
		}
	}

	if len(e.HandlesCapabilities) > 0 {
		fmt.Printf("\n  %s\n", dimStyle.Render("Handles capabilities:"))
		for _, cap := range e.HandlesCapabilities {
			fmt.Printf("    %s %s\n", successGreen.Render("•"), cap)
		}
	}

	if len(e.Tags) > 0 {
		fmt.Printf("\n  %s  %s\n", dimStyle.Render("Tags:"), dimStyle.Render(strings.Join(e.Tags, ", ")))
	}

	fmt.Println()
}

func packLabel(packID string, c *Catalog) string {
	for _, p := range c.Packs {
		if p.ID == packID {
			return fmt.Sprintf("%s  %s", packID, dimStyle.Render(p.Name))
		}
	}
	if packID == "" {
		return dimStyle.Render("(none)")
	}
	return packID
}

func riskTierStyled(tier string) string {
	switch strings.ToLower(tier) {
	case "high":
		return errorRed.Render(tier)
	case "medium":
		return warningOrange.Render(tier)
	case "low":
		return successGreen.Render(tier)
	default:
		return tier
	}
}

func blastScoreStyled(score int) string {
	s := fmt.Sprintf("%d", score)
	switch {
	case score >= 70:
		return errorRed.Render(s)
	case score >= 40:
		return warningOrange.Render(s)
	default:
		return successGreen.Render(s)
	}
}

// wordWrap breaks a string into lines of at most width characters.
func wordWrap(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	var current strings.Builder

	for _, w := range words {
		if current.Len() > 0 && current.Len()+1+len(w) > width {
			lines = append(lines, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(w)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}
