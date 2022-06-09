#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct bpf_map_def SEC("maps") blocked_ip_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(int),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") blocked_port_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(int),
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
		struct iphdr *ip = data + sizeof(*eth);
		if ((void*)ip + sizeof(*ip) <= data_end) {
			__u32 ip_src = ip->saddr;
			__u32 ip_dest = ip->daddr;
			int *value_src = bpf_map_lookup_elem(&blocked_ip_map, &ip_src);
			if (value_src) {
				if ((*value_src == 0) || (*value_src == 1)){
					return XDP_DROP;
				}
			}
			int *value_dest = bpf_map_lookup_elem(&blocked_ip_map, &ip_dest);
			if (value_dest) {
                                if ((*value_dest == 0) || (*value_dest == 2)){
                                        return XDP_DROP;
                                }
                        }

			int *value2 = bpf_map_lookup_elem(&blocked_port_map, &ip_src);
		}
	}
	return  XDP_PASS;
}

char _license[] SEC("license") = "GPL";