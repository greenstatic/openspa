package ipresolver

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
)

const DefaultEchoIpV4Server = "https://ipv4.ip.openspa.org"
const DefaultEchoIpV6Server = "https://ipv6.ip.openspa.org"

// Resolves the client's public IP by returning the public IP used by the client
// and the last proxy IP (in case any are in use).
type PublicResolver interface {
	GetPublicIP(string) (net.IP, net.IP, error)
}

// Echo-IP public resolver:
// https://github.com/greenstatic/echo-ip
type EchoIPPublicResolver struct {
}

// Returns the client's public IP with which they sent a HTTP POST request to a
// Echo-IP service. We send a HTTP POST request in case GET requests are cached.
// The resolverUrl string expects the URL of the Echo-IP resolver, this can
// be a http/https URL.
func (_ EchoIPPublicResolver) GetPublicIP(resolverUrl string) (ip net.IP, proxyIP net.IP, err error) {

	resp, err := http.Post(resolverUrl, "application/json", nil)
	if err != nil {
		return nil, nil, err
	}

	type IPDetails struct {
		RemoteIP      string `json:"remoteIP"`
		XForwardedFor string `json:"forwardedForIP"`
	}

	body := struct {
		Success   bool      `json:"success"`
		IP        string    `json:"ip"`
		IsIPv6    bool      `json:"isIpv6"`
		Datetime  string    `json:"datetime"`
		IPDetails IPDetails `json:"ipDetails"`
		Service   string    `json:"service"`
		Version   string    `json:"version"`
		SrcUrl    string    `json:"srcUrl"`
	}{}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithField("echoIpServer", resolverUrl).Error("Failed to read response")
		log.Error(err)
		return
	}
	log.WithField("resp", string(bodyBytes)).Debug("Response from Echo-IP")

	json.Unmarshal(bodyBytes, &body)

	if body.IPDetails.XForwardedFor != "" {
		proxyIP = net.ParseIP(body.IPDetails.RemoteIP)
	}

	ip = net.ParseIP(body.IP)
	return
}
