package agent_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/niccolofant/agent-go"
	"github.com/niccolofant/agent-go/candid/idl"
	"github.com/niccolofant/agent-go/certification/hashtree"
	"github.com/niccolofant/agent-go/identity"
	"github.com/niccolofant/agent-go/principal"
)

var (
	LEDGER_PRINCIPAL   = principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai")
	REGISTRY_PRINCIPAL = principal.MustDecode("rwlgt-iiaaa-aaaaa-aaaaa-cai")
)

var _ = new(testLogger)

func Example_anonymous_query() {
	a, _ := agent.New(agent.DefaultConfig, http.Client{})
	type Account struct {
		Account string `ic:"account"`
	}
	var balance struct {
		E8S uint64 `ic:"e8s"`
	}
	_ = a.Query(LEDGER_PRINCIPAL, "account_balance_dfx", []any{
		Account{"9523dc824aa062dcd9c91b98f4594ff9c6af661ac96747daef2090b7fe87037d"},
	}, []any{&balance})
	fmt.Println(balance.E8S)
	// Output:
	// 0
}

func Example_json() {
	raw := `{"e8s":1}`
	var balance struct {
		// Tags can be combined with json tags.
		E8S uint64 `ic:"e8s" json:"e8s"`
	}
	_ = json.Unmarshal([]byte(raw), &balance)
	fmt.Println(balance.E8S)

	a, _ := agent.New(agent.DefaultConfig, http.Client{})
	if err := a.Query(LEDGER_PRINCIPAL, "account_balance_dfx", []any{struct {
		Account string `json:"account"`
	}{
		Account: "9523dc824aa062dcd9c91b98f4594ff9c6af661ac96747daef2090b7fe87037d",
	}}, []any{&balance}); err != nil {
		fmt.Println(err)
	}
	rawJSON, _ := json.Marshal(balance)
	fmt.Println(string(rawJSON))
	// Output:
	// 1
	// {"e8s":0}
}

func Example_query_ed25519() {
	id, _ := identity.NewRandomEd25519Identity()
	ledgerID := principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai")
	a, _ := agent.New(agent.Config{Identity: id}, http.Client{})
	var balance struct {
		E8S uint64 `ic:"e8s"`
	}
	_ = a.Query(ledgerID, "account_balance_dfx", []any{map[string]any{
		"account": "9523dc824aa062dcd9c91b98f4594ff9c6af661ac96747daef2090b7fe87037d",
	}}, []any{&balance})
	fmt.Println(balance.E8S)
	// Output:
	// 0
}

func Example_query_prime256v1() {
	id, _ := identity.NewRandomPrime256v1Identity()
	ledgerID := principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai")
	a, _ := agent.New(agent.Config{Identity: id}, http.Client{})
	var balance struct {
		E8S uint64 `ic:"e8s"`
	}
	_ = a.Query(ledgerID, "account_balance_dfx", []any{map[string]any{
		"account": "9523dc824aa062dcd9c91b98f4594ff9c6af661ac96747daef2090b7fe87037d",
	}}, []any{&balance})
	fmt.Println(balance.E8S)
	// Output:
	// 0
}

func Example_query_secp256k1() {
	id, _ := identity.NewRandomSecp256k1Identity()
	ledgerID := principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai")
	a, _ := agent.New(agent.Config{Identity: id}, http.Client{})
	var balance struct {
		E8S uint64 `ic:"e8s"`
	}
	_ = a.Query(ledgerID, "account_balance_dfx", []any{map[string]any{
		"account": "9523dc824aa062dcd9c91b98f4594ff9c6af661ac96747daef2090b7fe87037d",
	}}, []any{&balance})
	fmt.Println(balance.E8S)
	// Output:
	// 0
}

func TestAgent_Call(t *testing.T) {
	a, err := agent.New(agent.DefaultConfig, http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := a.ReadStateCertificate(REGISTRY_PRINCIPAL, [][]hashtree.Label{{hashtree.Label("subnet")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range hashtree.ListPaths(n, nil) {
		if len(path) == 3 && string(path[0]) == "subnet" && string(path[2]) == "public_key" {
			subnetID := principal.Principal{Raw: []byte(path[1])}
			_ = subnetID
		}
	}
}

func TestAgent_Query_Ed25519(t *testing.T) {
	id, err := identity.NewRandomEd25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := agent.New(agent.Config{
		Identity: id,
	}, http.Client{})
	type Account struct {
		Account string `ic:"account"`
	}
	var balance struct {
		E8S uint64 `ic:"e8s"`
	}
	if err := a.Query(LEDGER_PRINCIPAL, "account_balance_dfx", []any{
		Account{"9523dc824aa062dcd9c91b98f4594ff9c6af661ac96747daef2090b7fe87037d"},
	}, []any{&balance}); err != nil {
		t.Fatal(err)
	}
}

func TestAgent_Query_Secp256k1(t *testing.T) {
	id, err := identity.NewRandomSecp256k1Identity()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := agent.New(agent.Config{
		Identity: id,
	}, http.Client{})
	type Account struct {
		Account string `ic:"account"`
	}
	var balance struct {
		E8S uint64 `ic:"e8s"`
	}
	if err := a.Query(LEDGER_PRINCIPAL, "account_balance_dfx", []any{
		Account{"9523dc824aa062dcd9c91b98f4594ff9c6af661ac96747daef2090b7fe87037d"},
	}, []any{&balance}); err != nil {
		t.Fatal(err)
	}
}

func TestAgent_Query_callback(t *testing.T) {
	a, err := agent.New(agent.DefaultConfig, http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	ledgerCanisterID := principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai")

	type GetBlocksArgs struct {
		Start  uint64 `ic:"start" json:"start"`
		Length uint64 `ic:"length" json:"length"`
	}

	type ArchivedBlocksRange struct {
		Start    uint64       `ic:"start" json:"start"`
		Length   uint64       `ic:"length" json:"length"`
		Callback idl.Function `ic:"callback" json:"callback"`
	}

	type QueryBlocksResponse struct {
		ChainLength     uint64                `ic:"chain_length" json:"chain_length"`
		Certificate     *[]byte               `ic:"certificate,omitempty" json:"certificate,omitempty"`
		Blocks          []any                 `ic:"blocks" json:"blocks"`
		FirstBlockIndex uint64                `ic:"first_block_index" json:"first_block_index"`
		ArchivedBlocks  []ArchivedBlocksRange `ic:"archived_blocks" json:"archived_blocks"`
	}

	args := GetBlocksArgs{
		Start:  123,
		Length: 1,
	}
	req, err := a.CreateCandidAPIRequest(
		agent.RequestTypeQuery,
		ledgerCanisterID,
		"query_blocks",
		args,
	)
	if err != nil {
		t.Fatal(err)
	}
	var out QueryBlocksResponse
	if err := req.Query([]any{&out}, false); err != nil {
		t.Fatal(err)
	}
	archive := out.ArchivedBlocks[0]
	if archive.Start != 123 || archive.Length != 1 {
		t.Error(archive)
	}
	if !archive.Callback.Method.Principal.Equal(principal.MustDecode("qjdve-lqaaa-aaaaa-aaaeq-cai")) {
		t.Error(archive.Callback.Method.Principal)
	}
	if archive.Callback.Method.Method != "get_blocks" {
		t.Error(archive.Callback.Method.Method)
	}

	type Timestamp struct {
		TimestampNanos uint64 `ic:"timestamp_nanos" json:"timestamp_nanos"`
	}

	type Tokens struct {
		E8s uint64 `ic:"e8s" json:"e8s"`
	}

	type Operation struct {
		Mint *struct {
			To     []byte `ic:"to" json:"to"`
			Amount Tokens `ic:"amount" json:"amount"`
		} `ic:"Mint,variant"`
		Burn *struct {
			From    []byte  `ic:"from" json:"from"`
			Spender *[]byte `ic:"spender,omitempty" json:"spender,omitempty"`
			Amount  Tokens  `ic:"amount" json:"amount"`
		} `ic:"Burn,variant"`
		Transfer *struct {
			From    []byte   `ic:"from" json:"from"`
			To      []byte   `ic:"to" json:"to"`
			Amount  Tokens   `ic:"amount" json:"amount"`
			Fee     Tokens   `ic:"fee" json:"fee"`
			Spender *[]uint8 `ic:"spender,omitempty" json:"spender,omitempty"`
		} `ic:"Transfer,variant"`
		Approve *struct {
			From              []byte     `ic:"from" json:"from"`
			Spender           []byte     `ic:"spender" json:"spender"`
			AllowanceE8s      idl.Int    `ic:"allowance_e8s" json:"allowance_e8s"`
			Allowance         Tokens     `ic:"allowance" json:"allowance"`
			Fee               Tokens     `ic:"fee" json:"fee"`
			ExpiresAt         *Timestamp `ic:"expires_at,omitempty" json:"expires_at,omitempty"`
			ExpectedAllowance *Tokens    `ic:"expected_allowance,omitempty" json:"expected_allowance,omitempty"`
		} `ic:"Approve,variant"`
	}

	type Transaction struct {
		Memo          uint64     `ic:"memo" json:"memo"`
		Icrc1Memo     *[]byte    `ic:"icrc1_memo,omitempty" json:"icrc1_memo,omitempty"`
		Operation     *Operation `ic:"operation,omitempty" json:"operation,omitempty"`
		CreatedAtTime Timestamp  `ic:"created_at_time" json:"created_at_time"`
	}

	type Block struct {
		ParentHash  *[]byte     `ic:"parent_hash,omitempty" json:"parent_hash,omitempty"`
		Transaction Transaction `ic:"transaction" json:"transaction"`
		Timestamp   Timestamp   `ic:"timestamp" json:"timestamp"`
	}

	type BlockRange struct {
		Blocks []Block `ic:"blocks" json:"blocks"`
	}

	type GetBlocksError struct {
		BadFirstBlockIndex *struct {
			RequestedIndex  uint64 `ic:"requested_index" json:"requested_index"`
			FirstValidIndex uint64 `ic:"first_valid_index" json:"first_valid_index"`
		} `ic:"BadFirstBlockIndex,variant"`
		Other *struct {
			ErrorCode    uint64 `ic:"error_code" json:"error_code"`
			ErrorMessage string `ic:"error_message" json:"error_message"`
		} `ic:"Other,variant"`
	}

	type GetBlocksResult struct {
		Ok  *BlockRange     `ic:"Ok,variant"`
		Err *GetBlocksError `ic:"Err,variant"`
	}

	var blocks GetBlocksResult
	if err := a.Query(
		archive.Callback.Method.Principal,
		archive.Callback.Method.Method,
		[]any{args},
		[]any{&blocks},
	); err != nil {
		t.Error(err)
	}

	if len(blocks.Ok.Blocks) != 1 {
		t.Error(blocks)
	}
}

type testLogger struct{}

func (t testLogger) Printf(format string, v ...any) {
	fmt.Printf("[TEST]"+format+"\n", v...)
}
