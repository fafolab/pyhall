package main

import (
	"fmt"
	"os"
	"regexp"

	"github.com/pyhall/pyhall-go/wcp"
	"github.com/spf13/cobra"
)

// newRegistryCmd returns the `pyhall registry` subcommand group.
func newRegistryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "pyhall.dev registry operations — verify workers, check hashes, view ban-list",
	}
	cmd.AddCommand(
		newRegistryVerifyCmd(),
		newRegistryCheckHashCmd(),
		newRegistryBanListCmd(),
		newRegistryStatusCmd(),
	)
	return cmd
}

// ── registry verify <worker-id> ───────────────────────────────────────────────

func newRegistryVerifyCmd() *cobra.Command {
	var registryURL string
	cmd := &cobra.Command{
		Use:   "verify <worker-id>",
		Short: "Show current attestation status for a worker",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			workerID := args[0]
			opts := wcp.RegistryClientOptions{}
			if registryURL != "" {
				opts.BaseURL = registryURL
			}
			rc := wcp.NewRegistryClient(opts)
			r, err := rc.Verify(workerID)
			if err != nil {
				if _, ok := err.(*wcp.RegistryRateLimitError); ok {
					fmt.Fprintln(os.Stderr, errorRed.Render("Rate limited — try again later"))
					os.Exit(1)
				}
				return err
			}

			statusRender := primaryBlue.Render
			if r.Status == "active" {
				statusRender = successGreen.Render
			} else if r.Status == "banned" {
				statusRender = errorRed.Render
			} else {
				statusRender = warningOrange.Render
			}

			fmt.Println()
			fmt.Printf("  %s  %s\n", dimStyle.Render("Worker:"), primaryBlue.Render(r.WorkerID))
			fmt.Printf("  %s  %s\n", dimStyle.Render("Status:"), statusRender(r.Status))
			hash := dimStyle.Render("none")
			if r.CurrentHash != nil {
				hash = *r.CurrentHash
			}
			fmt.Printf("  %s  %s\n", dimStyle.Render("Current hash:"), hash)
			banned := successGreen.Render("no")
			if r.Banned {
				banned = errorRed.Render("yes")
			}
			fmt.Printf("  %s  %s\n", dimStyle.Render("Banned:"), banned)
			if r.BanReason != nil {
				fmt.Printf("  %s  %s\n", dimStyle.Render("Ban reason:"), *r.BanReason)
			}
			attested := dimStyle.Render("never")
			if r.AttestedAt != nil {
				attested = *r.AttestedAt
			}
			fmt.Printf("  %s  %s\n", dimStyle.Render("Attested at:"), attested)
			ai := "no"
			if r.AIGenerated {
				ai = "yes"
			}
			fmt.Printf("  %s  %s\n", dimStyle.Render("AI generated:"), ai)
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&registryURL, "registry-url", "", "Registry base URL (default: $PYHALL_REGISTRY_URL or https://api.pyhall.dev)")
	return cmd
}

// ── registry check-hash <sha256> ──────────────────────────────────────────────

var sha256Re = regexp.MustCompile(`(?i)^[0-9a-f]{64}$`)

func newRegistryCheckHashCmd() *cobra.Command {
	var registryURL string
	cmd := &cobra.Command{
		Use:   "check-hash <sha256>",
		Short: "Check if a SHA-256 hash appears on the confirmed ban-list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sha256 := args[0]
			if !sha256Re.MatchString(sha256) {
				fmt.Fprintln(os.Stderr, errorRed.Render("Invalid sha256: must be 64 hex characters"))
				os.Exit(1)
			}

			opts := wcp.RegistryClientOptions{}
			if registryURL != "" {
				opts.BaseURL = registryURL
			}
			rc := wcp.NewRegistryClient(opts)
			banned, err := rc.IsHashBanned(sha256)
			if err != nil {
				if _, ok := err.(*wcp.RegistryRateLimitError); ok {
					fmt.Fprintln(os.Stderr, errorRed.Render("Rate limited — try again later"))
					os.Exit(1)
				}
				return err
			}

			fmt.Println()
			if banned {
				fmt.Printf("  %s   %s\n", errorRed.Render("BANNED"), sha256)
			} else {
				fmt.Printf("  %s    %s\n", successGreen.Render("CLEAN"), sha256)
				fmt.Printf("  %s\n", dimStyle.Render("Not found on the confirmed ban-list."))
			}
			fmt.Println()
			if banned {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryURL, "registry-url", "", "Registry base URL")
	return cmd
}

// ── registry ban-list ─────────────────────────────────────────────────────────

func newRegistryBanListCmd() *cobra.Command {
	var registryURL string
	var limit int
	cmd := &cobra.Command{
		Use:   "ban-list",
		Short: "Show the confirmed ban-list",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := wcp.RegistryClientOptions{}
			if registryURL != "" {
				opts.BaseURL = registryURL
			}
			rc := wcp.NewRegistryClient(opts)
			entries, err := rc.GetBanList(limit)
			if err != nil {
				if _, ok := err.(*wcp.RegistryRateLimitError); ok {
					fmt.Fprintln(os.Stderr, errorRed.Render("Rate limited — try again later"))
					os.Exit(1)
				}
				return err
			}

			fmt.Println()
			if len(entries) == 0 {
				fmt.Println(dimStyle.Render("  Ban-list is empty."))
				fmt.Println()
				return nil
			}

			fmt.Printf("  %s\n\n", primaryBlue.Render(fmt.Sprintf("Confirmed ban-list (%d entries):", len(entries))))
			for _, e := range entries {
				short := e.SHA256[:12] + "…"
				date := ""
				if len(e.ReportedAt) >= 10 {
					date = e.ReportedAt[:10]
				}
				reason := e.Reason
				if len(reason) > 60 {
					reason = reason[:60]
				}
				fmt.Printf("  %s  %s  %s  %s\n",
					errorRed.Render(short),
					dimStyle.Render(date),
					dimStyle.Render("["+e.Source+"]"),
					reason,
				)
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&registryURL, "registry-url", "", "Registry base URL")
	cmd.Flags().IntVar(&limit, "limit", 20, "Maximum entries to show")
	return cmd
}

// ── registry status ───────────────────────────────────────────────────────────

func newRegistryStatusCmd() *cobra.Command {
	var registryURL string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check registry API health and version",
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := wcp.RegistryClientOptions{}
			if registryURL != "" {
				opts.BaseURL = registryURL
			}
			rc := wcp.NewRegistryClient(opts)
			base := rc.BaseURL()
			h, err := rc.Health()
			if err != nil {
				fmt.Println()
				fmt.Printf("  %s  %s\n", dimStyle.Render("Registry:"), base)
				fmt.Printf("  %s  %s\n", errorRed.Render("Status:"), "unreachable ("+err.Error()+")")
				fmt.Println()
				os.Exit(1)
			}

			ok, _ := h["ok"].(bool)
			version, _ := h["version"].(string)
			statusStr := "degraded"
			statusRender := warningOrange.Render
			if ok {
				statusStr = "ok"
				statusRender = successGreen.Render
			}

			fmt.Println()
			fmt.Printf("  %s  %s\n", dimStyle.Render("Registry:"), base)
			fmt.Printf("  %s  %s\n", dimStyle.Render("Status:"), statusRender(statusStr))
			fmt.Printf("  %s  %s\n", dimStyle.Render("Version:"), version)
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&registryURL, "registry-url", "", "Registry base URL")
	return cmd
}
