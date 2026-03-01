package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and catalog statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loadCatalog()
			if err != nil {
				return err
			}

			wcpSpec := "0.1"
			if v, ok := c.Meta["wcp_spec"].(string); ok {
				wcpSpec = v
			}

			fmt.Println(primaryBlue.Render("pyhall CLI 0.1.0 (Go)"))
			fmt.Printf("WCP specification: %s\n", lightBlue.Render(wcpSpec))
			fmt.Printf("Taxonomy:          %s entities\n",
				primaryBlue.Render(fmt.Sprintf("%d", c.EntityCount())),
			)
			fmt.Printf("Built by:          %s\n", primaryBlue.Render("FΔFΌ★LΔB"))
			fmt.Printf("License:           %s\n", dimStyle.Render("Apache 2.0"))
			return nil
		},
	}
}
