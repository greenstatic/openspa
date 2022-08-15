package internal

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

const (
	IPv4ServerDefault = "https://ipv4.openspa.org"
	IPv6ServerDefault = "https://ipv6.openspa.org"
)

func GetIP(ipv4Server, ipv6Server string) {
	v4 := &PublicIPResolver{
		ServerURL: ipv4Server,
	}
	v6 := &PublicIPResolver{
		ServerURL: ipv6Server,
	}

	s := getIP(v4, v6)
	fmt.Printf(s)
}

type IPResolver interface {
	GetPublicIP() (net.IP, error)
}

func getIP(ipv4, ipv6 IPResolver) string {
	s := strings.Builder{}
	s.WriteString("Public IPv4: ")

	v4, err := ipv4.GetPublicIP()
	if err != nil {
		s.WriteString("\n")
		s.WriteString("Error: ")
		s.WriteString(err.Error())
		s.WriteString("\n")
	} else {
		s.WriteString(v4.String())
	}
	s.WriteString("\n")

	s.WriteString("Public IPv6: ")

	v6, err := ipv6.GetPublicIP()
	if err != nil {
		s.WriteString("\n")
		s.WriteString("Error: ")
		s.WriteString(err.Error())
		s.WriteString("\n")
	} else {
		s.WriteString(v6.String())
	}
	s.WriteString("\n")

	return s.String()
}

var _ IPResolver = &PublicIPResolver{}

type PublicIPResolver struct {
	ServerURL string
}

type publicIPResolverResponseBody struct {
	IP string `json:"IP"`
}

func (r *PublicIPResolver) GetPublicIP() (net.IP, error) {
	if r.ServerURL == "" {
		return nil, errors.New("invalid server url")
	}

	resp, err := http.Get(r.ServerURL)
	if err != nil {
		return nil, errors.Wrap(err, "get request failed")
	}

	b := publicIPResolverResponseBody{}

	d := json.NewDecoder(resp.Body)
	if err := d.Decode(&b); err != nil {
		return nil, errors.Wrap(err, "response decode")
	}

	ip := net.ParseIP(b.IP)
	if ip == nil {
		return nil, errors.New("ip parse")
	}

	return ip, nil
}
