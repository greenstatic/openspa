package cmdimpl

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/greenstatic/openspa/internal/ipresolver"
	"strconv"
)

func GetIP(echoIpServerIPv4, echoIpServerIPv6 string) error {
	log.WithFields(log.Fields{
		"echoIpServerIpv4": echoIpServerIPv4,
		"echoIpServerIpv6": echoIpServerIPv6,
	}).
		Debug("Using Echo-IP IP resolver to resolve IPv4/IPv6 IPs")
	resp, err := ipresolver.Resolve(echoIpServerIPv4, echoIpServerIPv6)
	if err != nil {
		log.WithFields(log.Fields{
			"echoIpServerIpv4": echoIpServerIPv4,
			"echoIpServerIpv6": echoIpServerIPv6,
		}).Error("Failed to resolve IPv4/IPv6 IPs")
		log.Error(err)
		return err
	}

	// IPv4
	if resp.NoIPv4Outbound && resp.NoIPv4Public {
		fmt.Printf("No IPv4 connectivity\n")
	} else {
		if resp.NoIPv4Outbound {
			fmt.Printf("Outbound IPv4: FAILED TO RESOLVE\n")
		} else {
			fmt.Printf("Outbound IPv4: %s\n", resp.OutboundIPv4.String())
		}

		if resp.NoIPv4Public {
			fmt.Printf("Public IPv4: FAILED TO RESOLVE\n")
		} else {
			fmt.Printf("Public IPv4: %s\n", resp.PublicIPv4.String())
		}

		lastProxyIPv4 := ""
		if resp.ProxyIPv4 != nil {
			lastProxyIPv4 = resp.ProxyIPv4.String()
		}
		fmt.Printf("Last public proxy IPv4: %s\n", lastProxyIPv4)

		if resp.NoIPv4Outbound || resp.NoIPv4Public {
			fmt.Printf("Client behind IPv4 NAT: SKIPPING\n")
		} else {
			fmt.Printf("Client behind IPv4 NAT: %s\n", strconv.FormatBool(resp.NatIPv4))
		}
	}

	fmt.Println("-----------------------------")

	// IPv6
	if resp.NoIPv6Outbound && resp.NoIPv6Public {
		fmt.Printf("No IPv6 connectivity\n")
	} else {
		if resp.NoIPv6Outbound {
			fmt.Printf("Outbound IPv6: FAILED TO RESOLVE\n")
		} else {
			fmt.Printf("Outbound IPv6: %s\n", resp.OutboundIPv6.String())
		}

		if resp.NoIPv6Public {
			fmt.Printf("Public IPv6: FAILED TO RESOLVE\n")
		} else {
			fmt.Printf("Public IPv6: %s\n", resp.PublicIPv6.String())
		}

		lastProxyIPv6 := ""
		if resp.ProxyIPv6 != nil {
			lastProxyIPv6 = resp.ProxyIPv6.String()
		}
		fmt.Printf("Last public proxy IPv6: %s\n", lastProxyIPv6)

		if resp.NoIPv6Outbound || resp.NoIPv6Public {
			fmt.Printf("Client behind IPv6 NAT: SKIPPING\n")
		} else {
			fmt.Printf("Client behind IPv6 NAT: %s\n", strconv.FormatBool(resp.NatIPv6))
		}
	}

	// that was a lot of if..else, it would be great if we somehow managed to make all of that
	// more elegant.

	return nil
}
