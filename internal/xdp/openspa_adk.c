// +build ignore

/* SPDX-License-Identifier: GPL-2.0 */
/* This file was modified based on multiple examples from https://github.com/xdp-project/xdp-tutorial */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

#include "openspa_adk.h"


char __license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_ACTION_MAX);
	__type(key, __u32);
	__type(value, struct stats_datarec);
} xdp_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, OSPA_STAT_ID_MAX);
	__type(key, __u32);
	__type(value, struct ospa_stat_datarec);
} xdp_openspa_stats_map SEC(".maps");

#define CONFIG_MAP_IDX_OPENSPA_SERVER_PORT 0
#define CONFIG_MAP_IDX_ADK_PROOF_FIRST 1
#define CONFIG_MAP_IDX_ADK_PROOF_LAST 2
// Number of ADK proofs in the config map
#define NO_ADK_PROOFS (CONFIG_MAP_IDX_ADK_PROOF_LAST - CONFIG_MAP_IDX_ADK_PROOF_FIRST)
#define CONFIG_MAP_SIZE CONFIG_MAP_IDX_ADK_PROOF_LAST + 1

// xdp_config_map contains (per key):
//   0: CONFIG_MAP_IDX_OPENSPA_SERVER_PORT => OpenSPA UDP server port
//   1: CONFIG_MAP_IDX_ADK_PROOF_FIRST     => ADK Proof array, first index
//   ...
//   CONFIG_MAP_IDX_ADK_PROOF_LAST         => ADK Proof array, last index
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CONFIG_MAP_SIZE);
	__type(key, __u32);
	__type(value, __u32);
} xdp_config_map SEC(".maps");


static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	struct stats_datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	rec->rx_packets++;
	rec->rx_bytes += (ctx->data_end - ctx->data);

	return action;
}

static __always_inline
int xdp_openspa_stats_record_action(struct xdp_md *ctx, __u32 id)
{
	if (id >= OSPA_STAT_ID_MAX)
		return -1;

	struct ospa_stat_datarec *rec = bpf_map_lookup_elem(&xdp_openspa_stats_map, &id);
	if (!rec)
		return -1;

	rec->value++;

	return 0;
}

/* Checks weather the adk proof is valid or not.
   -1: proof is invalid
   0: lookup error, proof check not performed
   1: proof is valid
*/
static __always_inline
int adk_proof_valid(struct xdp_md *ctx, __u32 *adk_proof)
{
    __u8 i = 0;

    if (adk_proof == NULL || *adk_proof == 0)
        return -1;

    #pragma unroll
    for (i = CONFIG_MAP_IDX_ADK_PROOF_FIRST; i <= CONFIG_MAP_IDX_ADK_PROOF_LAST; i++) {
        __u32 key = i;
        __u32 *val = bpf_map_lookup_elem(&xdp_config_map, &key);
        if (val == NULL) {
            return 0;
            break;
        }

        if (*val == *adk_proof) {
            return 1;
        }
    }

    return -1;
}

static __always_inline
__u16 openspa_server_port()
{
    __u32 key = CONFIG_MAP_IDX_OPENSPA_SERVER_PORT;
    __u32 *val;

    val = bpf_map_lookup_elem(&xdp_config_map, &key);
    if (!val)
        return 0;

    return *val;
}

SEC("xdp")
int xdp_openspa_adk(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    __u32 action = XDP_PASS; // default action
    int eth_type;
    int ip_type;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    struct udphdr *udphdr;
    struct ospahdr *ospahdr;
    __u32 adk_proof;
    __u16 ospa_server_port;

    struct hdr_cursor nh;
    nh.pos = data;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        action = XDP_ABORTED;
    	goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
    	ip_type = parse_iphdr(&nh, data_end, &iphdr);
    }
    else if (eth_type == bpf_htons(ETH_P_IPV6)) {
    	ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
    }
    else {
        // Default action, pass it up the GNU/Linux network stack to be handled
    	goto out;
    }

    if (ip_type != IPPROTO_UDP) {
        // We do not need to process non-UDP traffic, pass it up the GNU/Linux network stack to be handled
        goto out;
    }

    if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
        action = XDP_ABORTED;
        goto out;
    }

    ospa_server_port = openspa_server_port();
    if (ospa_server_port == 0) {
        goto out;
    }

    if (bpf_ntohs(udphdr->dest) != ospa_server_port) {
        // UDP datagram destination is not to the OpenSPA server
        goto out;
    }

    if (parse_ospahdr(&nh, data_end, &ospahdr) < 0) {
        // UDP datagram is not an OpenSPA packet
        xdp_openspa_stats_record_action(ctx, OSPA_STAT_ID_NOT_OPENSPA_PACKET);
        action = XDP_DROP;
        goto out;
    }

    if (potentially_ospa_packet(&nh, data_end, ospahdr) < 0) {
        // Not OpenSPA packet
        xdp_openspa_stats_record_action(ctx, OSPA_STAT_ID_NOT_OPENSPA_PACKET);
        action = XDP_DROP;
        goto out;
    }

    adk_proof = bpf_ntohl(ospahdr->adk_proof);

    if (adk_proof_valid(ctx, &adk_proof) <= 0) {
        xdp_openspa_stats_record_action(ctx, OSPA_STAT_ID_ADK_PROOF_INVALID);
        action = XDP_DROP;
        goto out;
    } else {
        // Proof is valid, default action (XDP_PASS)
        xdp_openspa_stats_record_action(ctx, OSPA_STAT_ID_ADK_PROOF_VALID);
    }

out:
	return xdp_stats_record_action(ctx, action);
}
