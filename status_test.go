package agent_test

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/niccolofant/agent-go"
)

var ic0URL, _ = url.Parse("https://icp-api.io")

func ExampleClient_Status() {
	c := agent.NewClient(agent.ClientConfig{Host: ic0URL}, http.Client{})
	status, _ := c.Status()
	fmt.Printf("%x...%x\n", status.RootKey[:4], status.RootKey[len(status.RootKey)-4:])
	// Output:
	// 30818230...1a0baaae
}
