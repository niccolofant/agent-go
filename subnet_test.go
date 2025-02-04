package agent

import (
	"net/http"
	"testing"

	"github.com/niccolofant/agent-go/certification"
	"github.com/niccolofant/agent-go/principal"
)

func TestAgent_GetSubnetMetrics(t *testing.T) {
	a, err := New(DefaultConfig, http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetSubnetMetrics(principal.MustDecode(certification.RootSubnetID)); err != nil {
		t.Fatal(err)
	}
}

func TestAgent_GetSubnets(t *testing.T) {
	a, err := New(DefaultConfig, http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetSubnets(); err != nil {
		t.Fatal(err)
	}
}

func TestAgent_GetSubnetsInfo(t *testing.T) {
	a, err := New(DefaultConfig, http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetSubnetsInfo(); err != nil {
		t.Fatal(err)
	}
}
