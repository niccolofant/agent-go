package agent

import (
	"errors"
	"math"
	"time"
)

// ErrInvalidIngressExpiry means an explicit expiry is not a future, positive
// Unix timestamp representable in int64 nanoseconds.
var ErrInvalidIngressExpiry = errors.New("invalid ingress expiry")

// RequestOptions controls construction of one signed request, not the agent.
type RequestOptions struct {
	// IngressExpiry is an absolute expiration time. Zero uses Config.IngressExpiry.
	// An explicit value must be in the future and representable in int64 Unix
	// nanoseconds. The network may reject an expiry outside its permitted window.
	// Expiry does not cancel a request that has already entered processing.
	IngressExpiry time.Time
}

func (a Agent) requestExpiry(opts RequestOptions) (uint64, error) {
	if opts.IngressExpiry.IsZero() {
		return a.expiryDate(), nil
	}
	// Check the range before UnixNano, whose result is undefined outside it.
	if opts.IngressExpiry.Before(time.Unix(0, 1)) || opts.IngressExpiry.After(time.Unix(0, math.MaxInt64)) {
		return 0, ErrInvalidIngressExpiry
	}
	expiry := opts.IngressExpiry.UnixNano()
	if expiry <= time.Now().UnixNano() {
		return 0, ErrInvalidIngressExpiry
	}
	return uint64(expiry), nil
}
