package internal

import (
	cryptography "crypto"
	"fmt"
	"net"
	"strings"
	"time"

	lib "github.com/greenstatic/openspa/pkg/openspalib"
	"github.com/greenstatic/openspa/pkg/openspalib/crypto"
	"github.com/greenstatic/openspa/pkg/openspalib/tlv"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

type RequestRoutineParameters struct {
	ReqParams  RequestRoutineReqParameters
	AutoMode   bool
	RetryCount int
	Timeout    time.Duration
}
type RequestRoutineReqParameters struct {
	ClientUUID      string
	ClientIP        net.IP
	ServerIP        net.IP
	ServerPort      int
	TargetProto     lib.InternetProtocolNumber
	TargetIP        net.IP
	TargetPortStart int
	TargetPortEnd   int
}

type RequestRoutineOpt struct {
	Sender UDPSender
}

var RequestRoutineOptDefault = RequestRoutineOpt{
	Sender: NewUDPSend(),
}

func RequestRoutine(p RequestRoutineParameters, cs crypto.CipherSuite, opt RequestRoutineOpt) error {
	rd := lib.RequestData{
		TransactionID:   lib.RandomTransactionID(),
		ClientUUID:      p.ReqParams.ClientUUID,
		ClientIP:        p.ReqParams.ClientIP,
		TargetProtocol:  p.ReqParams.TargetProto,
		TargetIP:        p.ReqParams.TargetIP,
		TargetPortStart: p.ReqParams.TargetPortStart,
		TargetPortEnd:   p.ReqParams.TargetPortEnd,
	}

	sAddr := net.UDPAddr{
		IP:   p.ReqParams.ServerIP,
		Port: p.ReqParams.ServerPort,
	}

	// TODO: implement auto-mode

	s := fmt.Sprintf("OpenSPA sending request for access to target (%s %s/%d)",
		rd.TargetIP, rd.TargetProtocol, rd.TargetPortStart)
	if rd.TargetPortEnd != rd.TargetPortEnd {
		s = fmt.Sprintf("%s-%d", s, rd.TargetPortEnd)
	}

	log.Debug().Msg(s)

	resp, err := performRequest(opt.Sender, cs, rd, sAddr, performRequestParameters{
		retryCount: p.RetryCount,
		timeout:    p.Timeout,
	})
	if err != nil {
		return errors.Wrap(err, "request failure")
	}

	if !(resp.Header.TransactionID == rd.TransactionID) {
		return fmt.Errorf("transaction id mismatch in response (%d != %d)", rd.TransactionID, resp.Header.TransactionID)
	}

	firewallC, err := lib.TLVFromContainer(resp.Body, lib.FirewallKey)
	if err != nil {
		return errors.Wrap(err, "no firewall tlv8 in body container")
	}

	dur, err := lib.DurationFromContainer(firewallC)
	if err != nil {
		return errors.Wrap(err, "duration from response container")
	}

	log.Info().Msgf("OpenSPA response received, access to target (%s %s/%d-%d) for %s (%d seconds)",
		rd.TargetIP, rd.TargetProtocol, rd.TargetPortStart, rd.TargetPortEnd, dur.String(), int(dur.Seconds()))

	return nil
}

func SetupClientCipherSuite(ospa OSPA) (crypto.CipherSuite, error) {
	return clientCipherSuiteFromOSPA(ospa)
}

func clientCipherSuiteFromOSPA(ospa OSPA) (crypto.CipherSuite, error) {
	priv, err := crypto.RSADecodePrivateKey(ospa.Crypto.RSA.Client.PrivateKey)
	if err != nil {
		return nil, errors.Wrap(err, "rsa decode client private key")
	}

	pub, err := crypto.RSADecodePublicKey(ospa.Crypto.RSA.Server.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "rsa decode server public key")
	}
	r := staticPublicKeyResolver{
		key: pub,
	}
	c := crypto.NewCipherSuite_RSA_SHA256_AES256CBC(priv, r)
	return c, nil
}

var _ crypto.PublicKeyResolver = &staticPublicKeyResolver{}

type staticPublicKeyResolver struct {
	key cryptography.PublicKey
}

func (r staticPublicKeyResolver) PublicKey(_, _ tlv.Container) (cryptography.PublicKey, error) {
	return r.key, nil
}

type performRequestParameters struct {
	retryCount int
	timeout    time.Duration
}

func performRequest(u UDPSender, c crypto.CipherSuite, d lib.RequestData, server net.UDPAddr,
	params performRequestParameters) (*lib.Response, error) {
	r, err := lib.NewRequest(d, c)
	if err != nil {
		return nil, errors.Wrap(err, "new request")
	}

	reqB, err := r.Marshal()
	if err != nil {
		return nil, errors.Wrap(err, "request marshal")
	}

	if params.retryCount < 0 {
		return nil, errors.New("retry count is not >0")
	}

	var respB []byte
	for i := 0; i < params.retryCount; i++ {
		if i > 0 {
			log.Info().Msgf("Retrying sending request")
		}
		respB, err = u.SendUDPRequest(reqB, server, params.timeout)
		if errors.Is(err, errSocketRead) {
			log.Info().Msgf("Request timeout")
			continue
		}
		if err != nil {
			return nil, errors.Wrap(err, "Request UDP send error")
		}

		break
	}

	if respB == nil {
		return nil, errors.New("no response")
	}

	resp, err := lib.ResponseUnmarshal(respB, c)
	if err != nil {
		return nil, errors.Wrap(err, "response unmarshal")
	}

	return resp, nil
}

// UDPSender abstraction exists so that we can use a different implementation that does not actually send UDP traffic
// which is useful during testing.
type UDPSender interface {
	SendUDPRequest(req []byte, dest net.UDPAddr, timeout time.Duration) ([]byte, error)
}

type UDPSend struct{}

func NewUDPSend() UDPSend {
	return UDPSend{}
}

var errSocketRead = errors.New("socket read")

func (UDPSend) SendUDPRequest(req []byte, dest net.UDPAddr, timeout time.Duration) ([]byte, error) {
	c, err := net.DialUDP("udp", nil, &dest)
	if err != nil {
		return nil, errors.Wrap(err, "dial udp")
	}

	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, errors.Wrap(err, "set deadline")
	}

	_, err = c.Write(req)
	if err != nil {
		return nil, errors.Wrap(err, "socket write")
	}

	respB := make([]byte, lib.MaxPDUSize)

	n, sIP, err := c.ReadFromUDP(respB)
	if err != nil {
		return nil, errors.Wrap(err, errSocketRead.Error())
	}

	if !sIP.IP.Equal(dest.IP) {
		return nil, errors.New("response ip does not match")
	}

	if sIP.Port != dest.Port {
		return nil, errors.New("response port does not match")
	}

	err = c.Close()

	return respB[:n], errors.Wrap(err, "close")
}

func ResolveClientsIPAndVersionBasedOnTargetIP(ipv4ResServer, ipv6ResServer string, target net.IP) (net.IP, error) {
	serverURL := ipv4ResServer

	if isIPv6(target) {
		serverURL = ipv6ResServer
	}

	resolver := PublicIPResolver{
		ServerURL: serverURL,
	}

	ip, err := resolver.GetPublicIP()
	if err != nil {
		return nil, errors.Wrap(err, "get public ip")
	}
	return ip, nil
}

func isIPv6(ip net.IP) bool {
	return strings.Contains(ip.String(), ":")
}
