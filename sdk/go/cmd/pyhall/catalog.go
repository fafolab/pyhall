package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Entity represents a single WCP taxonomy entity (capability, worker_species, control, etc.)
type Entity struct {
	ID                  string   `json:"id"`
	Type                string   `json:"type"`
	PackID              string   `json:"pack_id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	RiskTier            string   `json:"risk_tier,omitempty"`
	Level               string   `json:"level,omitempty"`
	Guarantee           string   `json:"guarantee,omitempty"`
	BlastScore          int      `json:"blast_score,omitempty"`
	RequiredControls    []string `json:"required_controls,omitempty"`
	HandlesCapabilities []string `json:"handles_capabilities,omitempty"`
	Tags                []string `json:"tags,omitempty"`
}

// Pack represents a WCP taxonomy pack (a named grouping of entities).
type Pack struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	EntityCount int    `json:"entity_count"`
}

// Catalog is the full WCP taxonomy catalog.
type Catalog struct {
	Meta     map[string]interface{} `json:"_meta"`
	Packs    []Pack                 `json:"packs"`
	Entities []Entity               `json:"entities"`
}

// catalog is the singleton loaded from the embedded JSON.
var catalog *Catalog

// loadCatalog parses the embedded catalog JSON.
func loadCatalog() (*Catalog, error) {
	if catalog != nil {
		return catalog, nil
	}
	var c Catalog
	if err := json.Unmarshal(catalogData, &c); err != nil {
		return nil, fmt.Errorf("failed to parse catalog: %w", err)
	}
	catalog = &c
	return catalog, nil
}

// scoreEntity returns a relevance score (0–100) for a query against an entity.
// Higher score = better match.
func scoreEntity(e Entity, query string) int {
	q := strings.ToLower(query)
	if strings.ToLower(e.ID) == q {
		return 100
	}
	if strings.Contains(strings.ToLower(e.ID), q) {
		return 80
	}
	if strings.Contains(strings.ToLower(e.Name), q) {
		return 70
	}
	if strings.Contains(strings.ToLower(e.Description), q) {
		return 40
	}
	// Also search tags
	for _, tag := range e.Tags {
		if strings.Contains(strings.ToLower(tag), q) {
			return 30
		}
	}
	return 0
}

// SearchResult pairs an entity with its relevance score.
type SearchResult struct {
	Entity Entity
	Score  int
}

// Search searches the catalog for entities matching the query.
// Returns results sorted by score descending, with score > 0.
func (c *Catalog) Search(query string) []SearchResult {
	var results []SearchResult
	for _, e := range c.Entities {
		score := scoreEntity(e, query)
		if score > 0 {
			results = append(results, SearchResult{Entity: e, Score: score})
		}
	}
	// Sort by score descending (simple insertion sort — catalog is small)
	for i := 1; i < len(results); i++ {
		for j := i; j > 0 && results[j].Score > results[j-1].Score; j-- {
			results[j], results[j-1] = results[j-1], results[j]
		}
	}
	return results
}

// FindByID looks up a single entity by its exact ID (case-insensitive).
func (c *Catalog) FindByID(id string) (*Entity, error) {
	id = strings.ToLower(id)
	for i, e := range c.Entities {
		if strings.ToLower(e.ID) == id {
			return &c.Entities[i], nil
		}
	}
	return nil, fmt.Errorf("entity %q not found in catalog", id)
}

// Browse returns entities filtered by optional packID and/or entityType.
// Pass empty string to skip that filter.
func (c *Catalog) Browse(packID, entityType string) []Entity {
	var out []Entity
	for _, e := range c.Entities {
		if packID != "" && e.PackID != packID {
			continue
		}
		if entityType != "" && e.Type != entityType {
			continue
		}
		out = append(out, e)
	}
	return out
}

// PackByID looks up a pack by ID.
func (c *Catalog) PackByID(id string) (*Pack, error) {
	for i, p := range c.Packs {
		if p.ID == id {
			return &c.Packs[i], nil
		}
	}
	return nil, fmt.Errorf("pack %q not found in catalog", id)
}

// EntityCount returns the total number of entities.
func (c *Catalog) EntityCount() int {
	return len(c.Entities)
}

// PackCount returns the total number of packs.
func (c *Catalog) PackCount() int {
	return len(c.Packs)
}
