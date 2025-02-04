package registry_test

import (
	"os"
	"testing"

	"github.com/niccolofant/agent-go/clients/registry"
)

func TestClient_GetNodeListSince(t *testing.T) {
	checkEnabled(t)

	c, err := registry.New()
	if err != nil {
		t.Fatal(err)
	}

	latestVersion, err := c.GetLatestVersion()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.GetNodeListSince(latestVersion - 100); err != nil {
		t.Fatal(err)
	}
}

func checkEnabled(t *testing.T) {
	// The reason for this is that the tests are very slow.
	if os.Getenv("REGISTRY_TEST_ENABLE") != "true" {
		t.Skip("Skipping registry tests. Set REGISTRY_TEST_ENABLE=true to enable.")
	}
}
