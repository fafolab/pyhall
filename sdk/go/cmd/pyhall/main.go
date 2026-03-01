package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

//go:embed taxonomy/catalog.json
var catalogData []byte

func main() {
	root := &cobra.Command{
		Use:   "pyhall",
		Short: "PyHall CLI — Worker Class Protocol (WCP) taxonomy browser and scaffold tool",
		Long: primaryBlue.Render("pyhall") + " — " + lightBlue.Render("Worker Class Protocol (WCP) CLI") + `

Browse the WCP taxonomy, explain entities, search capabilities,
and scaffold new workers with pre-filled registry records.

  pyhall version          Version and catalog stats
  pyhall search <query>   Fuzzy-search the taxonomy catalog
  pyhall explain <id>     Detailed info for a capability or worker species
  pyhall browse           Browse taxonomy (filter by pack or type)
  pyhall scaffold         Interactive worker scaffold wizard`,
		SilenceUsage: true,
	}

	root.AddCommand(
		newVersionCmd(),
		newSearchCmd(),
		newExplainCmd(),
		newBrowseCmd(),
		newScaffoldCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", errorRed.Render(err.Error()))
		os.Exit(1)
	}
}
