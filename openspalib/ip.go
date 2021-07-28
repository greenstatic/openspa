package openspalib

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net"
	"net/http"
)

const (
	PublicIPv4ResolverDefaultEndpoint = "https://ipv4.openspa.org"
)

var (
	ErrMissingIPFieldResp = errors.New("missing ip field in response")
)

// PublicIPv4Resolver resolved the callers public IPv4 address. This is particularly useful
// to resolve the public IP in case the client is behind a NAT.
type PublicIPv4Resolver struct {
	// Endpoint should be a URL (preferably HTTPS) that will return a JSON response with a
	// field `ip` or `ipv4` (case-insensitive).
	Endpoint string
}

func NewPublicIPv4Resolver(endpoint string) PublicIPv4Resolver {
	return PublicIPv4Resolver{Endpoint: endpoint}
}

func NewDefaultPublicIPv4Resolver() PublicIPv4Resolver {
	return PublicIPv4Resolver{Endpoint: PublicIPv4ResolverDefaultEndpoint}
}

func (r *PublicIPv4Resolver) Fetch() (net.IP, error) {
	resp, err := http.Get(r.Endpoint)
	if err != nil {
		return nil, errors.Wrap(err, "request error")
	}

	if sc := resp.StatusCode; sc != http.StatusOK {
		return nil, fmt.Errorf("http status code is not 200 but: %d", sc)
	}

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read all body")
	}

	return publicIPv4ResolverParseResponse(bytes)
}

type ipResolveResponse struct {
	IP string `json:""`
	IPv4 string `json:""`
}

func publicIPv4ResolverParseResponse(data []byte) (net.IP, error) {
	r := ipResolveResponse{}

	if err := json.Unmarshal(data, &r); err != nil {
		return nil, errors.Wrap(err, "json decode error")
	}

	ip := net.ParseIP(r.IP)
	ip2 := net.ParseIP(r.IPv4)

	if ip == nil && ip2 == nil {
		return nil, ErrMissingIPFieldResp
	}

	if ip == nil {
		return ip2, nil
	}

	return ip, nil
}