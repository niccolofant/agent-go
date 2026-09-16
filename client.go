package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/niccolofant/agent-go/principal"
)

// ic0 is the old (default) host for the Internet Computer.
// var ic0, _ = url.Parse("https://ic0.app/")

// icp0 is the default host for the Internet Computer.
var icp0, _ = url.Parse("https://icp0.io/")

const (
	headerICNodeID            = "X-Ic-Node-Id"
	headerICSubnetID          = "X-Ic-Subnet-Id"
	headerICCacheStatus       = "X-Ic-Cache-Status"
	headerICCacheBypassReason = "X-Ic-Cache-Bypass-Reason"
	headerICRetries           = "X-Ic-Retries"
	headerICErrorCause        = "X-Ic-Error-Cause"
)

// Client is a client for the IC agent.
type Client struct {
	client *http.Client
	routes RouteProvider
	logger Logger
	// callVersion / queryVersion / readStateVersion select the API version
	// segment of the corresponding endpoints. The defaults certify canister ranges
	// under the sharded /canister_ranges/<subnet_id> layout; legacy uses the
	// deprecated /subnet/<subnet_id>/canister_ranges layout.
	callVersion      string
	queryVersion     string
	readStateVersion string
}

// HTTPResponseMetadata contains IC routing metadata exposed by API boundary
// nodes. It is populated only by opt-in metadata methods so ordinary queries
// do not pay for header extraction.
type HTTPResponseMetadata struct {
	NodeID            string
	SubnetID          string
	CacheStatus       string
	CacheBypassReason string
	Retries           int
	StatusCode        int
	RetryAfter        time.Duration
}

// NewClient creates a new client based on the given configuration.
func NewClient(options ...ClientOption) Client {
	c := Client{
		client:           http.DefaultClient,
		routes:           StaticRoute(icp0),
		logger:           new(NoopLogger),
		callVersion:      "v4",
		queryVersion:     "v3",
		readStateVersion: "v3",
	}
	for _, o := range options {
		o(&c)
	}
	return c
}

func (c Client) Call(ctx context.Context, canisterID principal.Principal, data []byte) ([]byte, error) {
	u, err := c.url(fmt.Sprintf("/api/%s/canister/%s/call", c.callVersion, canisterID.Encode()))
	if err != nil {
		return nil, err
	}
	c.logger.Printf("[CLIENT] CALL %s", u)
	req, err := c.newRequest(ctx, "POST", u, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusAccepted:
		return nil, nil
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var reply struct {
			Status      string `cbor:"status"`
			Certificate []byte `cbor:"certificate"`
			RejectCode  uint64 `cbor:"reject_code"`
			Message     string `cbor:"reject_message"`
			ErrorCode   string `cbor:"error_code"`
		}
		if err := cbor.Unmarshal(body, &reply); err != nil {
			return nil, err
		}
		switch reply.Status {
		case "replied":
			return reply.Certificate, nil
		case "non_replicated_rejection":
			return nil, preprocessingError{
				RejectCode: reply.RejectCode,
				Message:    reply.Message,
				ErrorCode:  reply.ErrorCode,
			}
		default:
			return nil, fmt.Errorf("unknown status: %s", reply.Status)
		}
	default:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, newHTTPStatusError(resp, body)
	}
}

func (c Client) Query(ctx context.Context, canisterID principal.Principal, data []byte) ([]byte, error) {
	return c.post(ctx, c.queryVersion, "query", canisterID, data)
}

// QueryWithMetadata executes a query and returns API boundary routing metadata
// alongside the raw CBOR response.
func (c Client) QueryWithMetadata(ctx context.Context, canisterID principal.Principal, data []byte) ([]byte, HTTPResponseMetadata, error) {
	return c.postWithMetadata(ctx, c.queryVersion, "query", canisterID, data)
}

func (c Client) ReadState(ctx context.Context, canisterID principal.Principal, data []byte) ([]byte, error) {
	return c.post(ctx, c.readStateVersion, "read_state", canisterID, data)
}

func (c Client) ReadSubnetState(ctx context.Context, subnetID principal.Principal, data []byte) ([]byte, error) {
	return c.postSubnet(ctx, "read_state", subnetID, data)
}

// SetRouteProvider replaces the route provider used to pick a host URL for each
// outgoing request. Intended for runtime boundary-node selection (e.g. via
// DiscoverRoutes + RoundRobinRoute); not safe to call concurrently with
// in-flight requests.
func (c *Client) SetRouteProvider(rp RouteProvider) {
	c.routes = rp
}

// Status returns the status of the IC.
func (c Client) Status() (*Status, error) {
	raw, err := c.get("/api/v2/status")
	if err != nil {
		return nil, err
	}
	var status Status
	return &status, cbor.Unmarshal(raw, &status)
}

func (c Client) get(path string) ([]byte, error) {
	u, err := c.url(path)
	if err != nil {
		return nil, err
	}
	c.logger.Printf("[CLIENT] GET %s", u)
	resp, err := c.client.Get(u)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return io.ReadAll(resp.Body)
}

func (c Client) newRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/cbor")
	return req, nil
}

func (c Client) post(ctx context.Context, version, path string, canisterID principal.Principal, data []byte) ([]byte, error) {
	body, _, err := c.postResponse(ctx, version, path, canisterID, data, false)
	return body, err
}

func (c Client) postWithMetadata(ctx context.Context, version, path string, canisterID principal.Principal, data []byte) ([]byte, HTTPResponseMetadata, error) {
	return c.postResponse(ctx, version, path, canisterID, data, true)
}

func (c Client) postResponse(
	ctx context.Context,
	version, path string,
	canisterID principal.Principal,
	data []byte,
	withMetadata bool,
) ([]byte, HTTPResponseMetadata, error) {
	var metadata HTTPResponseMetadata
	u, err := c.url(fmt.Sprintf("/api/%s/canister/%s/%s", version, canisterID.Encode(), path))
	if err != nil {
		return nil, metadata, err
	}
	c.logger.Printf("[CLIENT] POST %s", u)
	req, err := c.newRequest(ctx, "POST", u, bytes.NewReader(data))
	if err != nil {
		return nil, metadata, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, metadata, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if withMetadata {
		metadata = responseMetadata(resp.Header)
		metadata.StatusCode = resp.StatusCode
		metadata.RetryAfter = retryAfter(resp.Header, time.Now())
	}
	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		return body, metadata, err
	default:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, metadata, err
		}
		return nil, metadata, newHTTPStatusError(resp, body)
	}
}

func responseMetadata(headers http.Header) HTTPResponseMetadata {
	metadata := HTTPResponseMetadata{
		NodeID:            headers.Get(headerICNodeID),
		SubnetID:          headers.Get(headerICSubnetID),
		CacheStatus:       headers.Get(headerICCacheStatus),
		CacheBypassReason: headers.Get(headerICCacheBypassReason),
	}
	if raw := headers.Get(headerICRetries); raw != "" {
		metadata.Retries, _ = strconv.Atoi(raw)
	}
	return metadata
}

func (c Client) postSubnet(ctx context.Context, path string, subnetID principal.Principal, data []byte) ([]byte, error) {
	u, err := c.url(fmt.Sprintf("/api/v2/subnet/%s/%s", subnetID.Encode(), path))
	if err != nil {
		return nil, err
	}
	c.logger.Printf("[CLIENT] POST %s", u)
	req, err := c.newRequest(ctx, "POST", u, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
		return io.ReadAll(resp.Body)
	default:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, newHTTPStatusError(resp, body)
	}
}

type httpStatusError struct {
	StatusCode int
	Status     string
	Body       []byte
	RetryDelay time.Duration
	Cause      string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("(%d) %s: %s", e.StatusCode, e.Status, e.Body)
}

// HTTPStatusCode and RetryAfter let callers implement endpoint cooldowns
// without depending on the concrete (intentionally private) error type.
func (e *httpStatusError) HTTPStatusCode() int { return e.StatusCode }

func (e *httpStatusError) RetryAfter() time.Duration { return e.RetryDelay }

// HTTPErrorCause exposes the boundary node's X-Ic-Error-Cause header, if
// present. Unknown values are preserved; callers own classification policy.
func (e *httpStatusError) HTTPErrorCause() string { return e.Cause }

func newHTTPStatusError(resp *http.Response, body []byte) *httpStatusError {
	return &httpStatusError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Body:       body,
		RetryDelay: retryAfter(resp.Header, time.Now()),
		Cause:      resp.Header.Get(headerICErrorCause),
	}
}

func retryAfter(headers http.Header, now time.Time) time.Duration {
	raw := headers.Get("Retry-After")
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(raw)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

func (c Client) url(p string) (string, error) {
	host, err := c.routes.Route()
	if err != nil {
		return "", fmt.Errorf("route: %w", err)
	}
	u := *host
	u.Path = path.Join(u.Path, p)
	return u.String(), nil
}

type ClientOption func(c *Client)

func WithHostURL(host *url.URL) ClientOption {
	return func(c *Client) {
		c.routes = StaticRoute(host)
	}
}

func WithHttpClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.client = client
	}
}

func WithLogger(logger Logger) ClientOption {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithLegacyAPI uses the deprecated /api/v3 call and /api/v2 query/read_state
// endpoints instead of the defaults (/api/v4 call, /api/v3 query/read_state).
func WithLegacyAPI() ClientOption {
	return func(c *Client) {
		c.callVersion = "v3"
		c.queryVersion = "v2"
		c.readStateVersion = "v2"
	}
}

type preprocessingError struct {
	// The reject code.
	RejectCode uint64 `cbor:"reject_code"`
	// A textual diagnostic message.
	Message string `cbor:"reject_message"`
	// An optional implementation-specific textual error code.
	ErrorCode string `cbor:"error_code"`
}

func (e preprocessingError) Error() string {
	return fmt.Sprintf("(%d) %s: %s", e.RejectCode, e.Message, e.ErrorCode)
}
