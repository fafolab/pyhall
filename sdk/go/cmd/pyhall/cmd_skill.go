// Copyright (c) 2026 pyhall.dev — https://pyhall.dev
// Licensed under the Apache License, Version 2.0 (see LICENSE)
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// defaultRegistryURL returns $PYHALL_REGISTRY_URL or falls back to the public registry.
func defaultRegistryURL() string {
	if u := os.Getenv("PYHALL_REGISTRY_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "https://api.pyhall.dev"
}

// newSkillCmd returns the `pyhall skill` subcommand group.
func newSkillCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "skill",
		Short: "Skill authoring and registry operations — init, build, certify, publish, install, verify",
	}
	cmd.AddCommand(
		newSkillInitCmd(),
		newSkillBuildCmd(),
		newSkillCertifyCmd(),
		newSkillPublishCmd(),
		newSkillInstallCmd(),
		newSkillVerifyCmd(),
	)
	return cmd
}

// ── skill init ────────────────────────────────────────────────────────────────

func newSkillInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Scaffold a new SKILL.md in the current directory",
		Long: `Create a SKILL.md template in the current directory.

The generated file follows the pyhall skill manifest format and can be
edited to describe your skill's capabilities, CLI reference, and safe
execution defaults.

  pyhall skill init`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dest := "SKILL.md"
			if _, err := os.Stat(dest); err == nil {
				fmt.Fprintln(os.Stderr, errorRed.Render("SKILL.md already exists in current directory"))
				os.Exit(1)
			}

			content := skillMDTemplate()
			if err := os.WriteFile(dest, []byte(content), 0644); err != nil {
				return fmt.Errorf("failed to write SKILL.md: %w", err)
			}

			fmt.Println()
			fmt.Printf("  %s  Created %s\n", successGreen.Render("Done!"), primaryBlue.Render(dest))
			fmt.Println()
			fmt.Printf("  %s\n", dimStyle.Render("Next steps:"))
			fmt.Printf("    1. Edit SKILL.md — fill in name, description, capabilities\n")
			fmt.Printf("    2. pyhall skill build   — compile adapter JSON files\n")
			fmt.Printf("    3. pyhall skill certify  — submit for registry certification\n")
			fmt.Println()
			return nil
		},
	}
}

func skillMDTemplate() string {
	year := time.Now().UTC().Year()
	return fmt.Sprintf(`---
name: my-skill
description: >
  A one-paragraph description of what this skill does and when to use it.
  Include the platforms it targets and what problems it solves.
license: Apache-2.0
compatibility: Claude Code, OpenAI Codex, and any Agent Skills-compatible tool
metadata:
  author: your-org
  version: "0.1.0"
  homepage: https://pyhall.dev
  repository: https://github.com/your-org/my-skill
  registry: https://api.pyhall.dev
---

# My Skill — Short Title

Short one-line summary of what this skill enables.

## What you can do

- **Action 1** — description of the first capability
- **Action 2** — description of the second capability
- **Action 3** — description of the third capability

## CLI quick reference

`+"```"+`bash
# Example commands
pyhall skill install my-skill   # install this skill
pyhall skill verify             # check integrity

# Add your skill's own commands here
`+"```"+`

## Safe execution defaults

Use least privilege by default:

1. Prefer read-only commands first (list, status, check, verify).
2. Require explicit operator confirmation before mutations (install, publish, register).
3. Never print raw secrets or tokens in output.
4. Deny-by-default on ambiguous context.

## Environment variables

`+"```"+`bash
PYHALL_API_KEY=your-api-key          # registry authentication
PYHALL_REGISTRY_URL=https://api.pyhall.dev  # override for self-hosted
`+"```"+`

## Getting started

1. Install: `+"`pyhall skill install your-org/my-skill`"+`
2. Verify:  `+"`pyhall skill verify`"+`
3. Full docs: https://pyhall.dev

## License

Apache 2.0 — Copyright %d your-org
`, year)
}

// ── skill build ───────────────────────────────────────────────────────────────

func newSkillBuildCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "build",
		Short: "Compile SKILL.md into platform adapter JSON files",
		Long: `Read SKILL.md from the current directory and generate adapter definitions
under ./skill-adapters/:

  mcp-tool.json      — Anthropic MCP tool definition
  openai-function.json — OpenAI function object
  gemini-function.json — Google Gemini function declaration

  pyhall skill build`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile("SKILL.md")
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintln(os.Stderr, errorRed.Render("SKILL.md not found in current directory"))
					fmt.Fprintln(os.Stderr, dimStyle.Render("Run 'pyhall skill init' to create one."))
					os.Exit(1)
				}
				return fmt.Errorf("failed to read SKILL.md: %w", err)
			}

			meta := parseSkillMeta(string(raw))

			if err := os.MkdirAll("skill-adapters", 0755); err != nil {
				return fmt.Errorf("failed to create skill-adapters/: %w", err)
			}

			if err := writeMCPAdapter(meta); err != nil {
				return err
			}
			if err := writeOpenAIAdapter(meta); err != nil {
				return err
			}
			if err := writeGeminiAdapter(meta); err != nil {
				return err
			}

			fmt.Println()
			fmt.Printf("  %s\n\n", successGreen.Render("Built 3 adapters → ./skill-adapters/"))
			fmt.Printf("    %s  skill-adapters/mcp-tool.json\n", dimStyle.Render("•"))
			fmt.Printf("    %s  skill-adapters/openai-function.json\n", dimStyle.Render("•"))
			fmt.Printf("    %s  skill-adapters/gemini-function.json\n", dimStyle.Render("•"))
			fmt.Println()
			fmt.Printf("  %s\n", dimStyle.Render("Next: pyhall skill certify"))
			fmt.Println()
			return nil
		},
	}
}

// skillMeta holds the parsed front-matter values from SKILL.md.
type skillMeta struct {
	Name        string
	Description string
	Version     string
	Author      string
	Homepage    string
}

// parseSkillMeta extracts name, description, version, author, and homepage from
// a SKILL.md YAML front-matter block. It is intentionally lenient — unknown
// fields and malformed values are silently ignored so that the build command
// does not fail on partially-filled templates.
func parseSkillMeta(content string) skillMeta {
	m := skillMeta{
		Name:        "my-skill",
		Description: "A pyhall skill.",
		Version:     "0.1.0",
		Author:      "unknown",
		Homepage:    "https://pyhall.dev",
	}

	// Locate the YAML front-matter block delimited by ---
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return m
	}
	block := parts[1]

	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") {
			m.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		} else if strings.HasPrefix(line, "description:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "description:"))
			if v != ">" && v != "" {
				m.Description = v
			}
		} else if strings.HasPrefix(line, "version:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "version:"))
			v = strings.Trim(v, `"'`)
			if v != "" {
				m.Version = v
			}
		} else if strings.HasPrefix(line, "  author:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "  author:"))
			if v != "" {
				m.Author = v
			}
		} else if strings.HasPrefix(line, "  homepage:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "  homepage:"))
			if v != "" {
				m.Homepage = v
			}
		}
	}

	// If description was a multi-line "> " block, grab the first non-empty
	// continuation line from the raw block.
	if m.Description == "A pyhall skill." {
		inDesc := false
		for _, line := range strings.Split(block, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "description:") {
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "description:"))
				if rest == ">" {
					inDesc = true
					continue
				}
				if rest != "" {
					m.Description = rest
				}
				break
			}
			if inDesc {
				if trimmed == "" {
					break
				}
				m.Description = trimmed
				break
			}
		}
	}

	return m
}

func writeMCPAdapter(m skillMeta) error {
	adapter := map[string]interface{}{
		"name":        m.Name,
		"description": m.Description,
		"inputSchema": map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
			"required":   []string{},
		},
		"metadata": map[string]interface{}{
			"version":  m.Version,
			"author":   m.Author,
			"homepage": m.Homepage,
		},
	}
	return writeAdapterJSON("skill-adapters/mcp-tool.json", adapter)
}

func writeOpenAIAdapter(m skillMeta) error {
	adapter := map[string]interface{}{
		"type": "function",
		"function": map[string]interface{}{
			"name":        strings.ReplaceAll(m.Name, "-", "_"),
			"description": m.Description,
			"parameters": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		},
	}
	return writeAdapterJSON("skill-adapters/openai-function.json", adapter)
}

func writeGeminiAdapter(m skillMeta) error {
	adapter := map[string]interface{}{
		"name":        strings.ReplaceAll(m.Name, "-", "_"),
		"description": m.Description,
		"parameters": map[string]interface{}{
			"type":       "OBJECT",
			"properties": map[string]interface{}{},
			"required":   []string{},
		},
	}
	return writeAdapterJSON("skill-adapters/gemini-function.json", adapter)
}

func writeAdapterJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

// ── skill certify ─────────────────────────────────────────────────────────────

func newSkillCertifyCmd() *cobra.Command {
	var registryURL string
	var token string
	cmd := &cobra.Command{
		Use:   "certify",
		Short: "Submit SKILL.md + adapters to pyhall registry for certification",
		Long: `Read SKILL.md and skill-adapters/ from the current directory and POST to
the pyhall registry certification endpoint. Requires a valid API token.

  pyhall skill certify [--registry-url URL] [--token TOKEN]`,
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL := registryURL
			if baseURL == "" {
				baseURL = defaultRegistryURL()
			}
			tok := token
			if tok == "" {
				tok = os.Getenv("PYHALL_API_KEY")
			}
			if tok == "" {
				fmt.Fprintln(os.Stderr, errorRed.Render("No API token — set PYHALL_API_KEY or use --token"))
				os.Exit(1)
			}

			skillRaw, err := os.ReadFile("SKILL.md")
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintln(os.Stderr, errorRed.Render("SKILL.md not found — run 'pyhall skill init' first"))
					os.Exit(1)
				}
				return fmt.Errorf("failed to read SKILL.md: %w", err)
			}

			adapters := map[string]json.RawMessage{}
			adapterFiles := []string{"mcp-tool.json", "openai-function.json", "gemini-function.json"}
			for _, f := range adapterFiles {
				data, readErr := os.ReadFile(filepath.Join("skill-adapters", f))
				if readErr == nil {
					adapters[strings.TrimSuffix(f, ".json")] = json.RawMessage(data)
				}
			}

			payload := map[string]interface{}{
				"skill_md": string(skillRaw),
				"adapters": adapters,
			}
			body, err := json.Marshal(payload)
			if err != nil {
				return fmt.Errorf("failed to marshal payload: %w", err)
			}

			url := baseURL + "/api/v1/skills/certify"
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("failed to build request: %w", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)

			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Fprintln(os.Stderr, errorRed.Render("Registry unreachable: "+err.Error()))
				os.Exit(1)
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(resp.Body)

			if resp.StatusCode == http.StatusTooManyRequests {
				fmt.Fprintln(os.Stderr, errorRed.Render("Rate limited — try again later"))
				os.Exit(1)
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "%s  HTTP %d: %s\n",
					errorRed.Render("Certification failed"),
					resp.StatusCode,
					strings.TrimSpace(string(respBody)),
				)
				os.Exit(1)
			}

			var result map[string]interface{}
			certID := ""
			if jsonErr := json.Unmarshal(respBody, &result); jsonErr == nil {
				for _, k := range []string{"cert_id", "certification_id", "id"} {
					if v, ok := result[k].(string); ok && v != "" {
						certID = v
						break
					}
				}
			}

			fmt.Println()
			if certID != "" {
				fmt.Printf("  %s  Certification ID: %s\n", successGreen.Render("Certified!"), primaryBlue.Render(certID))
			} else {
				fmt.Printf("  %s\n", successGreen.Render("Certified!"))
				fmt.Printf("  %s\n", dimStyle.Render(strings.TrimSpace(string(respBody))))
			}
			fmt.Println()
			fmt.Printf("  %s\n", dimStyle.Render("Next: pyhall skill publish"))
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&registryURL, "registry-url", "", "Registry base URL (default: $PYHALL_REGISTRY_URL or https://api.pyhall.dev)")
	cmd.Flags().StringVar(&token, "token", "", "API token (default: $PYHALL_API_KEY)")
	return cmd
}

// ── skill publish ─────────────────────────────────────────────────────────────

func newSkillPublishCmd() *cobra.Command {
	var registryURL string
	var token string
	var certID string
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish a certified skill to the pyhall registry",
		Long: `Publish the certified skill in the current directory to the pyhall registry.
Requires a valid cert-id from 'pyhall skill certify'.

  pyhall skill publish --cert-id <id> [--registry-url URL] [--token TOKEN]`,
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL := registryURL
			if baseURL == "" {
				baseURL = defaultRegistryURL()
			}
			tok := token
			if tok == "" {
				tok = os.Getenv("PYHALL_API_KEY")
			}
			if tok == "" {
				fmt.Fprintln(os.Stderr, errorRed.Render("No API token — set PYHALL_API_KEY or use --token"))
				os.Exit(1)
			}

			skillRaw, err := os.ReadFile("SKILL.md")
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Fprintln(os.Stderr, errorRed.Render("SKILL.md not found — run 'pyhall skill init' first"))
					os.Exit(1)
				}
				return fmt.Errorf("failed to read SKILL.md: %w", err)
			}
			meta := parseSkillMeta(string(skillRaw))

			payload := map[string]interface{}{
				"skill_name": meta.Name,
				"version":    meta.Version,
			}
			if certID != "" {
				payload["cert_id"] = certID
			}
			body, err := json.Marshal(payload)
			if err != nil {
				return fmt.Errorf("failed to marshal payload: %w", err)
			}

			url := baseURL + "/api/v1/skills/publish"
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("failed to build request: %w", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)

			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Fprintln(os.Stderr, errorRed.Render("Registry unreachable: "+err.Error()))
				os.Exit(1)
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(resp.Body)

			if resp.StatusCode == http.StatusTooManyRequests {
				fmt.Fprintln(os.Stderr, errorRed.Render("Rate limited — try again later"))
				os.Exit(1)
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "%s  HTTP %d: %s\n",
					errorRed.Render("Publish failed"),
					resp.StatusCode,
					strings.TrimSpace(string(respBody)),
				)
				os.Exit(1)
			}

			var result map[string]interface{}
			skillURL := ""
			if jsonErr := json.Unmarshal(respBody, &result); jsonErr == nil {
				for _, k := range []string{"url", "skill_url", "registry_url"} {
					if v, ok := result[k].(string); ok && v != "" {
						skillURL = v
						break
					}
				}
			}

			fmt.Println()
			if skillURL != "" {
				fmt.Printf("  %s  Skill URL: %s\n", successGreen.Render("Published!"), primaryBlue.Render(skillURL))
			} else {
				fmt.Printf("  %s\n", successGreen.Render("Published!"))
				fmt.Printf("  %s\n", dimStyle.Render(strings.TrimSpace(string(respBody))))
			}
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&registryURL, "registry-url", "", "Registry base URL (default: $PYHALL_REGISTRY_URL or https://api.pyhall.dev)")
	cmd.Flags().StringVar(&token, "token", "", "API token (default: $PYHALL_API_KEY)")
	cmd.Flags().StringVar(&certID, "cert-id", "", "Certification ID from 'pyhall skill certify'")
	return cmd
}

// ── skill install ─────────────────────────────────────────────────────────────

func newSkillInstallCmd() *cobra.Command {
	var registryURL string
	cmd := &cobra.Command{
		Use:   "install <skill-id>",
		Short: "Install a skill from the pyhall registry into .pyhall/skills/<skill-id>/",
		Long: `Download a skill from the pyhall registry and install it locally.

  pyhall skill install pyhall/pyhall-wcp
  pyhall skill install pyhall-langchain [--registry-url URL]`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			skillID := args[0]
			baseURL := registryURL
			if baseURL == "" {
				baseURL = defaultRegistryURL()
			}

			// Normalise skill-id for use as a directory name (replace / with -)
			dirName := strings.ReplaceAll(skillID, "/", "-")
			installDir := filepath.Join(".pyhall", "skills", dirName)

			if err := os.MkdirAll(installDir, 0755); err != nil {
				return fmt.Errorf("failed to create install directory: %w", err)
			}

			url := baseURL + "/api/v1/skills/" + url.PathEscape(skillID)
			client := &http.Client{Timeout: 30 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				fmt.Fprintln(os.Stderr, errorRed.Render("Registry unreachable: "+err.Error()))
				os.Exit(1)
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusTooManyRequests {
				fmt.Fprintln(os.Stderr, errorRed.Render("Rate limited — try again later"))
				os.Exit(1)
			}
			if resp.StatusCode == http.StatusNotFound {
				fmt.Fprintln(os.Stderr, errorRed.Render("Skill not found: "+skillID))
				os.Exit(1)
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "%s  HTTP %d\n", errorRed.Render("Install failed"), resp.StatusCode)
				os.Exit(1)
			}

			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("failed to read registry response: %w", err)
			}

			// Attempt to parse the registry response as a JSON envelope.
			// If it contains a "skill_md" field, write that as SKILL.md.
			// Otherwise, save the raw payload as skill.json.
			var envelope map[string]json.RawMessage
			if jsonErr := json.Unmarshal(respBody, &envelope); jsonErr == nil {
				if skillMDRaw, ok := envelope["skill_md"]; ok {
					// Unquote the JSON string value
					var mdContent string
					if unquoteErr := json.Unmarshal(skillMDRaw, &mdContent); unquoteErr == nil {
						if err := os.WriteFile(filepath.Join(installDir, "SKILL.md"), []byte(mdContent), 0644); err != nil {
							return fmt.Errorf("failed to write SKILL.md: %w", err)
						}
					}
				}

				// Write adapters if present
				if adaptersRaw, ok := envelope["adapters"]; ok {
					var adapters map[string]json.RawMessage
					if jsonErr := json.Unmarshal(adaptersRaw, &adapters); jsonErr == nil {
						adaptersDir := filepath.Join(installDir, "skill-adapters")
						if mkErr := os.MkdirAll(adaptersDir, 0755); mkErr == nil {
							for name, data := range adapters {
								_ = os.WriteFile(filepath.Join(adaptersDir, name+".json"), data, 0644)
							}
						}
					}
				}

				// Write manifest for integrity verification
				manifestPath := filepath.Join(installDir, "manifest.json")
				if _, hasMeta := envelope["metadata"]; !hasMeta {
					// Build a minimal manifest from the envelope
					minManifest := map[string]interface{}{
						"skill_id":     skillID,
						"installed_at": time.Now().UTC().Format(time.RFC3339),
						"hash":         hashBytes(respBody),
					}
					if data, err := json.MarshalIndent(minManifest, "", "  "); err == nil {
						_ = os.WriteFile(manifestPath, data, 0644)
					}
				} else {
					if data, err := json.MarshalIndent(envelope, "", "  "); err == nil {
						_ = os.WriteFile(manifestPath, data, 0644)
					}
				}
			} else {
				// Not JSON — save raw
				if err := os.WriteFile(filepath.Join(installDir, "skill.json"), respBody, 0644); err != nil {
					return fmt.Errorf("failed to write skill.json: %w", err)
				}
			}

			absInstallDir, _ := filepath.Abs(installDir)

			fmt.Println()
			fmt.Printf("  %s  %s\n", successGreen.Render("Installed!"), primaryBlue.Render(skillID))
			fmt.Printf("  %s  %s\n", dimStyle.Render("Path:"), absInstallDir)
			fmt.Println()
			fmt.Printf("  %s\n", dimStyle.Render("Run 'pyhall skill verify' to check integrity."))
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&registryURL, "registry-url", "", "Registry base URL (default: $PYHALL_REGISTRY_URL or https://api.pyhall.dev)")
	return cmd
}

// ── skill verify ─────────────────────────────────────────────────────────────

func newSkillVerifyCmd() *cobra.Command {
	var registryURL string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Check integrity of all skills installed in .pyhall/skills/",
		Long: `Read every skill installed under .pyhall/skills/, fetch the current hash from
the registry, and report whether each is verified or tampered.

  pyhall skill verify [--registry-url URL]`,
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL := registryURL
			if baseURL == "" {
				baseURL = defaultRegistryURL()
			}

			skillsDir := filepath.Join(".pyhall", "skills")
			entries, err := os.ReadDir(skillsDir)
			if err != nil {
				if os.IsNotExist(err) {
					fmt.Println()
					fmt.Printf("  %s\n", dimStyle.Render("No skills installed (.pyhall/skills/ not found)."))
					fmt.Printf("  %s\n", dimStyle.Render("Run 'pyhall skill install <skill-id>' to install skills."))
					fmt.Println()
					return nil
				}
				return fmt.Errorf("failed to read skills directory: %w", err)
			}

			if len(entries) == 0 {
				fmt.Println()
				fmt.Printf("  %s\n", dimStyle.Render("No skills installed."))
				fmt.Println()
				return nil
			}

			client := &http.Client{Timeout: 15 * time.Second}
			fmt.Println()

			anyTampered := false
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				skillID := entry.Name()
				skillDir := filepath.Join(skillsDir, skillID)

				localHash := computeSkillHash(skillDir)

				// Fetch registry hash
				url := baseURL + "/api/v1/skills/" + skillID + "/hash"
				regHash := ""
				regErr := ""

				resp, httpErr := client.Get(url)
				if httpErr != nil {
					regErr = httpErr.Error()
				} else {
					defer resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						body, _ := io.ReadAll(resp.Body)
						var result map[string]interface{}
						if jsonErr := json.Unmarshal(body, &result); jsonErr == nil {
							for _, k := range []string{"hash", "sha256", "content_hash"} {
								if v, ok := result[k].(string); ok && v != "" {
									regHash = v
									break
								}
							}
						}
					} else if resp.StatusCode == http.StatusNotFound {
						regErr = "not found in registry"
					} else {
						regErr = fmt.Sprintf("HTTP %d", resp.StatusCode)
					}
				}

				if regErr != "" {
					fmt.Printf("  %s  %s  %s\n",
						warningOrange.Render("UNKNOWN  "),
						primaryBlue.Render(skillID),
						dimStyle.Render("(registry: "+regErr+")"),
					)
				} else if regHash == "" {
					fmt.Printf("  %s  %s  %s\n",
						warningOrange.Render("NO HASH  "),
						primaryBlue.Render(skillID),
						dimStyle.Render("(registry returned no hash)"),
					)
				} else if localHash == regHash {
					fmt.Printf("  %s  %s\n",
						successGreen.Render("VERIFIED "),
						primaryBlue.Render(skillID),
					)
				} else {
					fmt.Printf("  %s  %s\n",
						errorRed.Render("TAMPERED "),
						primaryBlue.Render(skillID),
					)
					fmt.Printf("    %s  local:    %s\n", dimStyle.Render("hash"), localHash)
					fmt.Printf("    %s  registry: %s\n", dimStyle.Render("hash"), regHash)
					anyTampered = true
				}
			}

			fmt.Println()
			if anyTampered {
				fmt.Printf("  %s\n", errorRed.Render("One or more skills appear tampered. Re-install to fix."))
				fmt.Println()
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&registryURL, "registry-url", "", "Registry base URL (default: $PYHALL_REGISTRY_URL or https://api.pyhall.dev)")
	return cmd
}

// computeSkillHash produces a stable SHA-256 of the installed skill directory
// by hashing the sorted concatenation of all regular file contents.
func computeSkillHash(dir string) string {
	h := sha256.New()
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		h.Write([]byte(path))
		h.Write(data)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}

// hashBytes returns the hex SHA-256 of a byte slice.
func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
