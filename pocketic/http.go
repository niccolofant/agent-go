package pocketic

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type CreateHttpGatewayResponse struct {
	Created *HttpGatewayInfo `json:"Created,omitempty"`
	Error   *ErrorMessage    `json:"Error,omitempty"`
}

type ErrorMessage struct {
	Message string `json:"message"`
}

func (e ErrorMessage) Error() string {
	return e.Message
}

type HttpGatewayBackend interface {
	httpGatewayBackend()
}

type HttpGatewayBackendPocketICInstance struct {
	PocketIcInstance int `json:"PocketIcInstance"`
}

func (HttpGatewayBackendPocketICInstance) httpGatewayBackend() {}

type HttpGatewayBackendReplica struct {
	Replica string `json:"Replica"`
}

func (HttpGatewayBackendReplica) httpGatewayBackend() {}

type HttpGatewayConfig struct {
	ListenAt  *int               `json:"listen_at,omitempty"`
	ForwardTo HttpGatewayBackend `json:"forward_to"`
}

func (h *HttpGatewayConfig) UnmarshalJSON(bytes []byte) error {
	var raw struct {
		ListenAt  *int            `json:"listen_at,omitempty"`
		ForwardTo json.RawMessage `json:"forward_to"`
	}
	if err := json.Unmarshal(bytes, &raw); err != nil {
		return err
	}
	h.ListenAt = raw.ListenAt

	var pocketIC HttpGatewayBackendPocketICInstance
	if err := json.Unmarshal(bytes, &pocketIC); err == nil {
		h.ForwardTo = pocketIC
		return nil
	}
	var replica HttpGatewayBackendReplica
	if err := json.Unmarshal(bytes, &replica); err == nil {
		h.ForwardTo = replica
		return nil
	}
	return fmt.Errorf("unknown HttpGatewayBackend type")
}

type HttpGatewayInfo struct {
	InstanceID int `json:"instance_id"`
	Port       int `json:"port"`
}

// AutoProgress configures the IC to make progress automatically, i.e., periodically update the time of the IC to the
// real time and execute rounds on the subnets. Returns the URL at which `/api/v2` requests for this instance can be made.
func (pic PocketIC) AutoProgress() error {
	now := time.Now()
	if err := pic.SetTime(now); err != nil {
		return err
	}
	return pic.do(
		http.MethodPost,
		fmt.Sprintf("%s/auto_progress", pic.instanceURL()),
		http.StatusOK,
		nil,
		nil,
	)
}

// MakeLive creates an HTTP gateway for this IC instance listening on an optionally specified port and configures the IC
// instance to make progress automatically, i.e., periodically update the time of the IC to the real time and execute
// rounds on the subnets. Returns the URL at which `/api/v2` requests for this instance can be made.
func (pic PocketIC) MakeLive(port *int) (string, error) {
	if err := pic.AutoProgress(); err != nil {
		return "", err
	}
	// Gateway already running.
	if pic.httpGateway != nil {
		return fmt.Sprintf("http://127.0.0.1:%d", pic.httpGateway.Port), nil
	}
	var resp CreateHttpGatewayResponse
	if err := pic.do(
		http.MethodPost,
		fmt.Sprintf("http://127.0.0.1:%d/http_gateway", pic.server.port),
		http.StatusCreated,
		HttpGatewayConfig{
			ListenAt: port,
			ForwardTo: HttpGatewayBackendPocketICInstance{
				PocketIcInstance: pic.InstanceID,
			},
		},
		&resp,
	); err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", resp.Error
	}
	return fmt.Sprintf("http://127.0.0.1:%d", resp.Created.Port), nil
}

// SetTime sets the current time of the IC, on all subnets.
func (pic PocketIC) SetTime(time time.Time) error {
	return pic.do(
		http.MethodPost,
		fmt.Sprintf("%s/update/set_time", pic.instanceURL()),
		http.StatusOK,
		RawTime{
			NanosSinceEpoch: int(time.UnixNano()),
		},
		nil,
	)
}
