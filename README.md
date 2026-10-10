# Go Agent for the Internet Computer

[![Go Version](https://img.shields.io/github/go-mod/go-version/aviate-labs/agent-go.svg)](https://github.com/niccolofant/agent-go)
[![GoDoc Reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/niccolofant/agent-go)

```shell
go get github.com/niccolofant/agent-go
```

## Getting Started

The agent is a library that allows you to talk to the Internet Computer.

```go
package main

import (
	"github.com/niccolofant/agent-go"
	"log"

	"github.com/niccolofant/agent-go/principal"
)

type (
	Account struct {
		Account string `ic:"account"`
	}

	Balance struct {
		E8S uint64 `ic:"e8s"`
	}
)

func main() {
	a, _ := agent.New(agent.DefaultConfig)

	var balance Balance
	if err := a.Query(
		principal.MustDecode("ryjl3-tyaaa-aaaaa-aaaba-cai"), "account_balance_dfx",
		[]any{Account{"9523dc824aa062dcd9c91b98f4594ff9c6af661ac96747daef2090b7fe87037d"}},
		[]any{&balance},
	); err != nil {
		log.Fatal(err)
	}

	_ = balance // Balance{E8S: 0}
}

```

### Using an Identity

Supported identities are `Ed25519`, `Secp256k1`, and `Prime256v1`. By default, the agent uses the anonymous identity.

```go
id, _ := identity.NewEd25519Identity(publicKey, privateKey)
config := agent.Config{
    Identity: id,
}
```

### Using the Local Replica

If you are running a local replica, you can use the `FetchRootKey` option to fetch the root key from the replica.

```go
u, _ := url.Parse("http://localhost:8000")
config := agent.Config{
    ClientConfig: []agent.ClientOption{agent.WithHostURL(u)},
    FetchRootKey: true,
    DisableSignedQueryVerification: true,
}
```

### Request Timing

Timing controls are independent when explicitly configured:

| Config field | Bounds | Default |
| --- | --- | --- |
| `IngressExpiry` | Signed envelope validity from construction | 5 minutes |
| `CallTimeout` | Initial update HTTP request | Inherits `IngressExpiry` |
| `QueryTimeout` | Query exchange and synchronous verification-key reads | Inherits `IngressExpiry` |
| `CertificateMaxAge` | Accepted age of call/read-state certificates | Inherits `IngressExpiry` |
| `ReadStateTimeout` | Each read-state HTTP request | 5 seconds |
| `PollTimeout` | Result-poll loop after the initial call | 10 seconds |
| `PollDelay` | Delay between result polls | 1 second |

The three new controls reject negative values. Their zero values preserve
existing behavior, including when `IngressExpiry` is customized. Caller
deadlines and any underlying HTTP client timeout can impose a tighter bound.
The query deadline does not preempt local decoding or cryptographic work.
`CertificateMaxAge` also sets the query-verification key cache's age policy;
it does not certify a query's application state or impose a query-response age.
Increasing it accepts older certified state, including older verification keys,
and weakens replay protection. A value below normal certification lag plus clock
skew can reject legitimate replies. Choose it from those requirements, not from
the desired envelope TTL.

Use `RequestOptions{IngressExpiry: time.Now().Add(ttl)}` with
`CreateAPIRequestWithOptions`, `CreateCandidAPIRequestWithOptions`,
`CreateProtoAPIRequestWithOptions` or `CreateRawAPIRequestWithOptions` to choose
an absolute expiry for one request. Zero uses the agent default. Explicit
expiries must be future positive timestamps representable in int64 Unix
nanoseconds; the network still enforces its own permitted expiry window.
Expiry is checked after argument encoding, before signing. Signer and dispatch
latency can consume the remaining validity; construction does not guarantee
that a later submission will still be valid.

Options do not mutate the shared agent or change HTTP/certificate/poll limits.
Reusing a prepared request reuses its signed bytes, request ID and expiry; it
does not renew the expiry. Persist the original request identity for recovery.
An update's expiry, a cancelled wait or a transport timeout is **not proof of
non-execution**. Poll the original request status rather than automatically
constructing a replacement. Expiry does not undo a request already processing.
See the [IC HTTPS interface](https://docs.internetcomputer.org/references/ic-interface-spec/https-interface/).

### Signed Call Recovery

`request.ExportCall()` returns an owned, authenticated `PreparedCall` snapshot.
Persist its `Envelope()` bytes and request metadata in durable intent storage
before transmission. `agent.RestorePreparedCall(raw)` verifies a saved envelope
against that agent's configured signing identity and preserves its exact bytes,
request ID, and ingress expiry. Neither API submits, retries, signs a replacement,
fetches a root key, or queries request status. Slice getters return copies.

This opt-in API supports direct self-authenticating signed calls with the SDK's
Ed25519, P-256 and secp256k1 identities, not anonymous calls, queries, delegations
or management-canister routing. It rejects unknown/duplicate fields, invalid
wire types, indefinite CBOR, and unsupported tags. Recovery is bounded to 2 MiB,
method names to 1..128 ASCII bytes (0x21..0x7e), nonces to absent or 1..32 bytes,
and expiry to positive int64 Unix nanoseconds.
An explicit empty nonce is rejected because field presence affects request IDs.
Existing call/query APIs are unchanged.

Expired envelopes are accepted for reconciliation, **not permission to resend**.
Authentication does not establish submission, execution, acceptable arguments,
maximum debit or settlement. Applications must independently check those, retain
unresolved reservations, and compare every recovered metadata field.
`RootKeyHash()` records the agent's local trust context; the ingress signature
does not bind a network. Compare it to independently trusted configuration,
never a root inferred from the envelope. Keep identity/root configuration
immutable in use and protect stored signed bytes as a submission capability.
Deduplicate by request ID, not envelope bytes: equivalent encodings/signatures
can have the same request ID. Authentication does not guarantee replica
acceptance under the network's signature and expiry policies.

## Packages

You can find the documentation for each package in the links below. Examples can be found throughout the documentation.

| Package Name      | Links                                                                                                                                                                                                   | Description                                                                     |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `agent`           | [![README](https://img.shields.io/badge/-README-green)](https://github.com/niccolofant/agent-go) [![DOC](https://img.shields.io/badge/-DOC-blue)](https://pkg.go.dev/github.com/niccolofant/agent-go)   | A library to talk directly to the Replica.                                      |
| `candid`          | [![DOC](https://img.shields.io/badge/-DOC-blue)](https://pkg.go.dev/github.com/niccolofant/agent-go/candid)                                                                                             | A Candid library for Golang.                                                    |
| `certification`   | [![DOC](https://img.shields.io/badge/-DOC-blue)](https://pkg.go.dev/github.com/niccolofant/agent-go/certification)                                                                                        | A Certification library for Golang.                                             |
| `gen`             | [![DOC](https://img.shields.io/badge/-DOC-blue)](https://pkg.go.dev/github.com/niccolofant/agent-go/gen)                                                                                                | A library to generate Golang clients.                                           |
| `identity`        | [![DOC](https://img.shields.io/badge/-DOC-blue)](https://pkg.go.dev/github.com/niccolofant/agent-go/identity)                                                                                           | A library that creates/manages identities.                                      |
| `principal`       | [![DOC](https://img.shields.io/badge/-DOC-blue)](https://pkg.go.dev/github.com/niccolofant/agent-go/principal)                                                                                          | Generic Identifiers for the Internet Computer                                   |
| `ic-go`           | [![DOC](https://img.shields.io/badge/-DOC-blue)](https://pkg.go.dev/github.com/aviate-labs/ic-go)                                                                                                       | Multiple auto-generated sub-modules to talk to the Internet Computer services   |
| `pocketic-go`     | [![DOC](https://img.shields.io/badge/-DOC-blue)](https://pkg.go.dev/github.com/aviate-labs/pocketic-go)                                                                                                 | A client library to talk to the PocketIC Server.                                |

More dependencies in the [go.mod](./go.mod) file.

## CLI

```shell
go install github.com/niccolofant/agent-go/cmd/goic@latest
```

Read more [here](cmd/goic/README.md)

## Testing

This repository contains two types of tests: standard Go tests and [PocketIC](https://github.com/dfinity/pocketic)
-dependent tests. The test suite runs a local PocketIC server using the installed pocket-ic-server to execute some
end-to-end (e2e) tests. If pocket-ic-server is not installed, those specific tests will be skipped.

```shell
go test -v ./...
```

## Candid Recursive Records

Wire decoding rejects values that enter mandatory record-only cycles, returning
`idl.ErrUninhabitedRecord` instead of overflowing the process stack. Classification
preserves the type graph and applies to generic, typed, skipped-field and raw
decoding. Absent optionals, empty vectors, unchosen variants and finite recursive
lists remain supported. Backward-only type tables avoid the classification walk.
This is not a general value-depth, memory or decode-work quota; callers must still
bound response sizes, and further decoder resource limits remain separate work.

`idl.RecordType` now contains private classification state. Use keyed literals or
`idl.NewRecordType`, not unkeyed literals; structural comparison tools may need to
ignore unexported fields. Programmatically built graphs are trusted input. Call
`idl.MarkUninhabitedRecords` with a complete resolved table before decoding such
graphs, and reclassify after editing fields. Classification and graph mutation
must not race with decoding.

## Reference Implementations

- [Rust Agent](https://github.com/dfinity/agent-rs/)
- [JavaScript Agent](https://github.com/dfinity/agent-js/)
