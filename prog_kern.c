#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>

struct bpf_map_def SEC("maps") blocked_ip4_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(int),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") blocked_ip6_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(__int128),
        .value_size  = sizeof(int),
        .max_entries = 20,
};


struct bpf_map_def SEC("maps") blocked_port_t_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u16),
	.value_size  = sizeof(int),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") blocked_port_u_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(__u16),
        .value_size  = sizeof(int),
        .max_entries = 20,
};

SEC("xdp_filter")
int  xdp_filter_func(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void*)eth + sizeof(*eth) <= data_end) {
		if (ntohs(eth->h_proto) == ETH_P_IP) {
			struct iphdr *ip = data + sizeof(*eth);
			if ((void*)ip + sizeof(*ip) <= data_end) {
				__u32 ip_src = ip->saddr;
				__u32 ip_dest = ip->daddr;
				int *value_src = bpf_map_lookup_elem(&blocked_ip4_map, &ip_src);
				if (value_src) {
					if ((*value_src == 0) || (*value_src == 1)){
						return XDP_DROP;
					}
				}
				int *value_dest = bpf_map_lookup_elem(&blocked_ip4_map, &ip_dest);
				if (value_dest) {
                                	if ((*value_dest == 0) || (*value_dest == 2)){
                                        	return XDP_DROP;
                        	        }
                        	}
				if (ip->protocol == IPPROTO_TCP) {
					struct tcphdr *tcp = (void*)ip + sizeof(*ip);
					if ((void*)tcp + sizeof(*tcp) <= data_end) {
						__u16 tcp_src = tcp->source;
						int *tcp_value_src = bpf_map_lookup_elem(&blocked_port_t_map, &tcp_src);
						__u16 tcp_dest = tcp->dest;
						int *tcp_value_dest = bpf_map_lookup_elem(&blocked_port_t_map, &tcp_dest);
						if (tcp_value_src) {
                 					return XDP_DROP;
						}
						/*if (tcp_value_dest) { //верификатор ругается
							return XDP_DROP;
						}*/
					}
				}
				if (ip->protocol == IPPROTO_UDP) {
					struct udphdr *udp = (void*)ip + sizeof(*ip);
					if ((void*)udp + sizeof(*udp) <= data_end) {
						__u16 udp_src = udp->source;
						int *udp_value_src = bpf_map_lookup_elem(&blocked_port_u_map, &udp_src);
                                                __u16 udp_dest = udp->dest;
                                                int *udp_value_dest = bpf_map_lookup_elem(&blocked_port_u_map, &udp_dest);
						if (udp_value_src) {
							return XDP_DROP;
						}
						/*if (udp_value_dest) { //верификатор ругается
                                                        return XDP_DROP;
                                                }*/
					}
				}
			}
			return XDP_PASS;
		}
		if (ntohs(eth->h_proto) == ETH_P_IPV6) {
			struct ipv6hdr *ip6 = data + sizeof(*eth);
			if ((void*)ip6 + sizeof(struct ipv6hdr) <= data_end) {
                        	struct in6_addr ip_src = ip6->saddr;
                        	struct in6_addr ip_dest = ip6->daddr;
				int *value_src = bpf_map_lookup_elem(&blocked_ip6_map, &ip_src.s6_addr);
				if (value_src) {
                                        if ((*value_src == 0) || (*value_src == 1)){
                                                return XDP_DROP;
                                        }
                                }
                                int *value_dest = bpf_map_lookup_elem(&blocked_ip6_map, &ip_dest.s6_addr);
                                if (value_dest) {
                                        if ((*value_dest == 0) || (*value_dest == 2)){
                                                return XDP_DROP;
                                        }
                                }
				if (ip6->nexthdr == IPPROTO_TCP) {
					struct tcphdr *tcp = (void*)ip6 + sizeof(*ip6);
                                        if ((void*)tcp + sizeof(*tcp) <= data_end) {
                                                __u16 tcp_src = tcp->source;
                                                int *tcp_value_src = bpf_map_lookup_elem(&blocked_port_t_map, &tcp_src);
                                                __u16 tcp_dest = tcp->dest;
                                                int *tcp_value_dest = bpf_map_lookup_elem(&blocked_port_t_map, &tcp_dest);
                                                if (tcp_value_src) {
                                                        return XDP_DROP;
                                                }
                                                /*if (tcp_value_dest) { //верификатор ругается
                                                        return XDP_DROP;
                                                }*/
                                        }
				}
				if (ip6->nexthdr == IPPROTO_UDP) {
					struct udphdr *udp = (void*)ip6 + sizeof(*ip6);
                                        if ((void*)udp + sizeof(*udp) <= data_end) {
                                                __u16 udp_src = udp->source;
                                                int *udp_value_src = bpf_map_lookup_elem(&blocked_port_u_map, &udp_src);
                                                __u16 udp_dest = udp->dest;
                                                int *udp_value_dest = bpf_map_lookup_elem(&blocked_port_u_map, &udp_dest);
                                                if (udp_value_src) {
                                                        return XDP_DROP;
                                                }
                                                /*if (udp_value_dest) { //верификатор ругается
                                                        return XDP_DROP;
                                                }*/
                                        } // перенести потом в отдельную функцию, чтобы не повторять код
				}
			}
		return XDP_PASS;
		}
	}
	return  XDP_PASS;
}

char _license[] SEC("license") = "GPL";
