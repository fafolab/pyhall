package main

import (
	"testing"
)

// TestCatalogLoads verifies the embedded catalog JSON parses without error.
func TestCatalogLoads(t *testing.T) {
	// Reset singleton so we test fresh parse
	catalog = nil

	c, err := loadCatalog()
	if err != nil {
		t.Fatalf("loadCatalog() error: %v", err)
	}
	if c == nil {
		t.Fatal("loadCatalog() returned nil catalog")
	}
	if c.EntityCount() == 0 {
		t.Error("catalog has 0 entities — expected > 0")
	}
	// WCP §3.0: No pack numbers. Catalog has no packs array.
	t.Logf("catalog loaded: %d entities", c.EntityCount())
}

// TestSearchFindsResults verifies that a common search term returns results.
func TestSearchFindsResults(t *testing.T) {
	catalog = nil
	c, err := loadCatalog()
	if err != nil {
		t.Fatalf("loadCatalog() error: %v", err)
	}

	results := c.Search("summarize")
	if len(results) == 0 {
		t.Error("Search(\"summarize\") returned 0 results — expected at least 1")
	}
	t.Logf("Search(\"summarize\") returned %d results", len(results))

	// All results must have score > 0
	for _, r := range results {
		if r.Score <= 0 {
			t.Errorf("result %q has score %d — expected > 0", r.Entity.ID, r.Score)
		}
	}
}

// TestSearchNoResults verifies that gibberish returns an empty result set.
func TestSearchNoResults(t *testing.T) {
	catalog = nil
	c, err := loadCatalog()
	if err != nil {
		t.Fatalf("loadCatalog() error: %v", err)
	}

	results := c.Search("xQzKfNpWmRtLvBsYjHdCuE99999")
	if len(results) != 0 {
		t.Errorf("Search(gibberish) returned %d results — expected 0", len(results))
	}
}

// TestExplainKnownEntity verifies lookup by a known entity ID succeeds.
func TestExplainKnownEntity(t *testing.T) {
	catalog = nil
	c, err := loadCatalog()
	if err != nil {
		t.Fatalf("loadCatalog() error: %v", err)
	}

	// Use the first entity from the catalog for deterministic lookup
	if c.EntityCount() == 0 {
		t.Skip("catalog is empty")
	}
	knownID := c.Entities[0].ID
	t.Logf("looking up first entity: %q", knownID)

	e, err := c.FindByID(knownID)
	if err != nil {
		t.Fatalf("FindByID(%q) error: %v", knownID, err)
	}
	if e.ID == "" {
		t.Error("FindByID returned entity with empty ID")
	}
	if e.Name == "" {
		t.Errorf("entity %q has empty Name", knownID)
	}
}

// TestExplainUnknownEntity verifies that an unknown ID returns an error.
func TestExplainUnknownEntity(t *testing.T) {
	catalog = nil
	c, err := loadCatalog()
	if err != nil {
		t.Fatalf("loadCatalog() error: %v", err)
	}

	_, err = c.FindByID("cap.does.not.exist.ever.xqz99")
	if err == nil {
		t.Error("FindByID(unknown) returned nil error — expected an error")
	}
	t.Logf("Got expected error: %v", err)
}
