/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/* This file was modified based on multiple examples from https://github.com/xdp-project/xdp-tutorial */

#ifndef __OPENSPA_ADK_H
#define __OPENSPA_ADK_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

/* Holds statistics about the XDP action we took */
struct stats_datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

#define OSPA_CTRL_VERSION 2
#define OSPA_CTRL_VERSION_MASK 0x70
#define OSPA_CTRL_VERSION_OFFSET 4
// Empirically the lowest bound value, not protocol wise
#define OSPA_BODY_MIN_SIZE 42

/* OpenSPA Header */
struct ospahdr {
    __u8 ctrl; // Control field
    __u8 tid;  // Transaction ID
    __u8 cipher_suite;
    __u8 reserved;
    __be32 adk_proof;
};

enum ospa_stat_id {
    OSPA_STAT_ID_NOT_OPENSPA_PACKET = 0,
    OSPA_STAT_ID_ADK_PROOF_INVALID,
    OSPA_STAT_ID_ADK_PROOF_VALID,
};

struct ospa_stat_datarec {
    __u64 value;
};

#define OSPA_STAT_ID_MAX (OSPA_STAT_ID_ADK_PROOF_VALID + 1)

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
/* Struct for collecting VLANs after parsing via parse_ethhdr_vlan */
struct collect_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr_vlan(struct hdr_cursor *nh,
					     void *data_end,
					     struct ethhdr **ethhdr,
					     struct collect_vlans *vlans)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK);

		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	/* Expect compiler removes the code that collects VLAN ids */
	return parse_ethhdr_vlan(nh, data_end, ethhdr, NULL);
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	/* Sanity check packet field is valid */
	if(hdrsize < sizeof(*iph))
		return -1;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;

	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
					void *data_end,
					struct udphdr **udphdr)
{
	int len = 0;
	struct udphdr *h = nh->pos;

	if (h + 1 > data_end)
        return -1;

	nh->pos  = h + 1;
	*udphdr = h;

	len = bpf_ntohs(h->len) - sizeof(struct udphdr);
	if (len < 0)
		return -1;

	return len;
}

static __always_inline int parse_ospahdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct ospahdr **ospahdr)
{
    struct ospahdr *h = nh->pos;
    if (h + 1 > data_end)
        return -1;

    nh->pos = h + 1;
    *ospahdr = h;

    return 0;
}

/* Checks to see if the data is potentially an OpenSPA packet.
    Returns:
      * 0 if it is potentially an OpenSPA packet
      * -1 if it is definitely not an OpenSPA packet.
*/
static __always_inline int potentially_ospa_packet(struct hdr_cursor *nh,
                    void *data_end,
                    struct ospahdr *ospahdr)
{
    int len;
    __u8 version;

    len = data_end - nh->pos;
    if (len < OSPA_BODY_MIN_SIZE)
        return -1;

    version = (ospahdr->ctrl & OSPA_CTRL_VERSION_MASK) >> OSPA_CTRL_VERSION_OFFSET;
    if (version != 0x02) {
        return -1;
    }

    return 0;
}


#endif /* __OPENSPA_ADK_H */