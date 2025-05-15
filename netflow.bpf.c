//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define flow key (5-tuple)
struct flow_key {
    __u32 src_ip;      // IPv4 source address
    __u32 dst_ip;      // IPv4 destination address
    __u16 src_port;    // Source port
    __u16 dst_port;    // Destination port
    __u8 protocol;     // Protocol (TCP=6, UDP=17)
};

// Define flow metrics
struct flow_metrics {
    __u64 packets;     // Packet count
    __u64 bytes;       // Byte count
    __u64 start_ts;    // Flow start timestamp (ns)
    __u64 last_ts;     // Last packet timestamp (ns)
};

// Define NetFlow record to send to user space
struct netflow_record {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u64 packets;
    __u64 bytes;
    __u64 start_ts;
    __u64 end_ts;
};

// BPF hash map to store flow metrics
//BPF_HASH(flow_table, struct flow_key, struct flow_metrics, 65536);
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64 * 1024);
	__type(key, struct flow_key);
	__type(value, struct flow_metrics);
} flow_table SEC(".maps");

// BPF ring buffer to send NetFlow records to user space
//BPF_RINGBUF(netflow_ringbuf, 1 << 20); // 1MB ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  /* 1 MB */
} netflow_ringbuf SEC(".maps");

// Helper to process IPv4 packets
static __always_inline int process_ipv4(struct __sk_buff *skb, __u8 is_ingress) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct flow_key key = {};
    struct flow_metrics *metrics;
    __u64 ts = bpf_ktime_get_ns();

    // Validate Ethernet header
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // Only handle TCP and UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // Extract transport layer header
    void *trans = (void *)ip + (ip->ihl * 4);
    if (trans + sizeof(__u16) * 2 > data_end)
        return TC_ACT_OK;

    __u16 *ports = trans;
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.src_port = ports[0];
    key.dst_port = ports[1];
    key.protocol = ip->protocol;

    // Normalize flow key for bidirectional flows
    if (is_ingress) {
        __u32 tmp_ip = key.src_ip;
        key.src_ip = key.dst_ip;
        key.dst_ip = tmp_ip;
        __u16 tmp_port = key.src_port;
        key.src_port = key.dst_port;
        key.dst_port = tmp_port;
    }

    // Update flow metrics
    metrics = bpf_map_lookup_elem(&flow_table, &key);
    if (!metrics) {
        struct flow_metrics new_metrics = {
            .packets = 1,
            .bytes = bpf_ntohs(ip->tot_len),
            .start_ts = ts,
            .last_ts = ts,
        };
        bpf_map_update_elem(&flow_table, &key, &new_metrics, BPF_ANY);
        metrics = &new_metrics;
    } else {
        metrics->packets++;
        metrics->bytes += bpf_ntohs(ip->tot_len);
        metrics->last_ts = ts;
    }

    // Periodically export flows (every 60 seconds)
    if (ts - metrics->start_ts > 60 * 1000000000ULL) {
        struct netflow_record *record = bpf_ringbuf_reserve(&netflow_ringbuf, sizeof(*record), 0);
        if (record) {
            record->src_ip = key.src_ip;
            record->dst_ip = key.dst_ip;
            record->src_port = key.src_port;
            record->dst_port = key.dst_port;
            record->protocol = key.protocol;
            record->packets = metrics->packets;
            record->bytes = metrics->bytes;
            record->start_ts = metrics->start_ts;
            record->end_ts = ts;
            bpf_ringbuf_submit(record, 0);

            // Reset metrics
            metrics->packets = 0;
            metrics->bytes = 0;
            metrics->start_ts = ts;
        }
    }

    return TC_ACT_OK;
}

SEC("tc_ingress")
int tc_ingress_func(struct __sk_buff *skb) {
    return process_ipv4(skb, 1);
}

SEC("tc_egress")
int tc_egress_func(struct __sk_buff *skb) {
    return process_ipv4(skb, 0);
}

char _license[] SEC("license") = "GPL";
