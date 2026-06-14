// SPDX-License-Identifier: Apache-2.0
//
// OpenScrub XDP data plane.
//
// Drops or rate-limits inbound traffic at the earliest possible
// kernel hook (XDP). Userspace populates four maps:
//
//   blocklist_v4   LPM_TRIE  IPv4 prefix → 1 = drop
//   blocklist_v6   LPM_TRIE  IPv6 prefix → 1 = drop
//   ratelimit      HASH      src IP (v4 only for v1.0.0) → token bucket
//   stats          PERCPU_ARRAY  counters indexed by STAT_*
//
// SYN cookie path:
//   For TCP SYN packets to listeners declared in `syncookie_listeners`
//   (key = dst port, value = 1), we call bpf_tcp_gen_syncookie to mint
//   a cookie, build a SYN-ACK in place, swap eth/ip/tcp endpoints and
//   XDP_TX the reply. The follow-up ACK is validated by the kernel
//   stack's standard SYN cookie path (sysctl net.ipv4.tcp_syncookies=2).
//   Hosts whose kernel lacks bpf_tcp_gen_syncookie (< 5.8) fall through
//   to the rate limiter, which is the v1.0.0 baseline defence.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_BLOCKLIST_V4         100000
#define MAX_BLOCKLIST_V6         50000
#define MAX_RATELIMIT            100000
#define MAX_SYNCOOKIE_LISTENERS  4096
#define NS_PER_SEC         1000000000ULL

// Stat counter indices (PERCPU_ARRAY keys).
enum stat_kind {
    STAT_PACKETS_PASSED      = 0,
    STAT_PACKETS_DROPPED     = 1,
    STAT_PACKETS_RATELIMITED = 2,
    STAT_PACKETS_MALFORMED   = 3,
    STAT_SYN_COOKIES_SENT    = 4,
    STAT__MAX                = 5,
};

struct lpm_v4_key {
    __u32 prefixlen;
    __u32 addr;        // network byte order
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8  addr[16];
};

struct ratelimit_value {
    __u64 tokens;          // available tokens (scaled by 1e9)
    __u64 last_refill_ns;  // bpf_ktime_get_ns at last refill
    __u32 rate_pps;        // refill rate in packets/sec
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, MAX_BLOCKLIST_V4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u8);
    __uint(max_entries, MAX_BLOCKLIST_V6);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocklist_v6 SEC(".maps");

// HASH (not PERCPU_HASH) — the token bucket is shared across CPUs and
// therefore intentionally racy: concurrent ratelimit_allow() calls on
// the same src IP race on rv->tokens / rv->last_refill_ns. The race is
// bounded (we only over- or under-shoot by ~NCPU tokens per refill
// window) and acceptable for a coarse PPS limiter; using PERCPU_HASH
// would multiply the configured PPS by NCPU and break the contract
// the operator sees in the API. Do not "fix" this by switching the
// map type without updating SetRatelimit() and the operator-facing
// docs.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                  // IPv4 src addr
    __type(value, struct ratelimit_value);
    __uint(max_entries, MAX_RATELIMIT);
} ratelimit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT__MAX);
} stats SEC(".maps");

// dst port (host order) → 1 = enable SYN cookies for this listener.
// Userspace populates this from the control plane.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, MAX_SYNCOOKIE_LISTENERS);
} syncookie_listeners SEC(".maps");

static __always_inline void stat_inc(enum stat_kind kind)
{
    __u32 k = (__u32)kind;
    __u64 *c = bpf_map_lookup_elem(&stats, &k);
    if (c)
        (*c)++;
}

// Token bucket: refill since last_refill_ns then attempt to consume 1 packet.
// Returns 1 if allowed, 0 if rate-limited.
static __always_inline int ratelimit_allow(__u32 src_v4)
{
    struct ratelimit_value *rv = bpf_map_lookup_elem(&ratelimit, &src_v4);
    if (!rv)
        return 1; // no rule for this source

    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - rv->last_refill_ns;
    if (elapsed > NS_PER_SEC * 60)
        elapsed = NS_PER_SEC * 60; // cap to avoid overflow

    __u64 capacity = (__u64)rv->rate_pps * NS_PER_SEC;
    __u64 refill   = (__u64)rv->rate_pps * elapsed;

    __u64 tokens = rv->tokens + refill;
    if (tokens > capacity)
        tokens = capacity;

    rv->last_refill_ns = now;

    if (tokens >= NS_PER_SEC) {
        rv->tokens = tokens - NS_PER_SEC;
        return 1;
    }
    rv->tokens = tokens;
    return 0;
}

// Compute IP header checksum from scratch over `len` bytes starting at iph.
static __always_inline __u16 ipv4_csum(struct iphdr *iph)
{
    iph->check = 0;
    __u32 csum = 0;
    __u16 *p = (__u16 *)iph;
    #pragma unroll
    for (int i = 0; i < (int)(sizeof(struct iphdr) >> 1); i++)
        csum += p[i];
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

// Fold a 32-bit one's-complement sum back into a 16-bit checksum.
static __always_inline __u16 csum_fold(__u64 csum)
{
    csum = (csum & 0xffffffff) + (csum >> 32);
    csum = (csum & 0xffff)     + (csum >> 16);
    csum = (csum & 0xffff)     + (csum >> 16);
    return ~csum;
}

// Build a SYN-ACK in place from an inbound TCP SYN, mint a SYN cookie
// via the kernel helper, and return XDP_TX. On any failure we fall
// back to XDP_PASS so the kernel stack handles it normally.
static __always_inline int try_syncookie_reply(struct xdp_md *ctx,
                                               struct ethhdr *eth,
                                               struct iphdr *ip,
                                               struct tcphdr *tcp,
                                               void *data_end)
{
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Only handle pure SYN (no ACK, no RST, no FIN).
    if (!tcp->syn || tcp->ack || tcp->rst || tcp->fin)
        return XDP_PASS;

    __u16 dport_h = bpf_ntohs(tcp->dest);
    __u8 *enabled = bpf_map_lookup_elem(&syncookie_listeners, &dport_h);
    if (!enabled || !*enabled)
        return XDP_PASS;

    __u32 cookie = bpf_tcp_gen_syncookie(tcp, sizeof(*tcp),
                                         (struct iphdr *)ip, sizeof(*ip),
                                         tcp, sizeof(*tcp));
    // Helper returns 0 on unsupported kernel / invalid input.
    if (cookie == 0)
        return XDP_PASS;

    // Snapshot the inbound TCP header *before* mutation. The TCP
    // checksum is recomputed incrementally via bpf_csum_diff over the
    // delta between old and new headers — the IP pseudo-header
    // contribution is invariant under src/dst swap (a+b == b+a in
    // one's-complement), so only the TCP header itself contributes
    // to the diff.
    struct tcphdr old_tcp = *tcp;
    __u32 client_seq = bpf_ntohl(tcp->seq);

    // Swap Ethernet src/dst.
    __u8 mac_tmp[ETH_ALEN];
    __builtin_memcpy(mac_tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, mac_tmp, ETH_ALEN);

    // Swap IPv4 src/dst.
    __u32 ip_tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = ip_tmp;
    ip->ttl = 64;
    ip->check = ipv4_csum(ip);

    // Swap TCP ports.
    __u16 port_tmp = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = port_tmp;

    // Build SYN-ACK: ack = client_seq + 1, seq = cookie, ACK flag set.
    tcp->ack_seq = bpf_htonl(client_seq + 1);
    tcp->seq     = bpf_htonl(cookie);
    tcp->ack     = 1;
    tcp->syn     = 1;

    // Recompute TCP checksum via incremental diff over the header.
    // Zero the checksum fields on both copies so they are excluded
    // from the diff (the existing checksum is then re-applied as the
    // seed below).
    __u16 old_check = old_tcp.check;
    old_tcp.check = 0;
    struct tcphdr new_tcp_for_diff = *tcp;
    new_tcp_for_diff.check = 0;

    __u64 csum = (__u16)~old_check;
    csum = bpf_csum_diff((__be32 *)&old_tcp, sizeof(old_tcp),
                         (__be32 *)&new_tcp_for_diff, sizeof(new_tcp_for_diff),
                         (__u32)csum);
    tcp->check = csum_fold(csum);

    stat_inc(STAT_SYN_COOKIES_SENT);
    return XDP_TX;
}

SEC("xdp")
int openscrub_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_inc(STAT_PACKETS_MALFORMED);
        return XDP_PASS;
    }

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            stat_inc(STAT_PACKETS_MALFORMED);
            return XDP_PASS;
        }

        struct lpm_v4_key key = {
            .prefixlen = 32,
            .addr      = ip->saddr,
        };
        __u8 *blocked = bpf_map_lookup_elem(&blocklist_v4, &key);
        if (blocked && *blocked) {
            stat_inc(STAT_PACKETS_DROPPED);
            return XDP_DROP;
        }

        if (!ratelimit_allow(ip->saddr)) {
            stat_inc(STAT_PACKETS_RATELIMITED);
            return XDP_DROP;
        }

        // SYN-flood mitigation for declared listeners.
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
            if ((void *)(tcp + 1) <= data_end) {
                int verdict = try_syncookie_reply(ctx, eth, ip, tcp, data_end);
                if (verdict == XDP_TX)
                    return XDP_TX;
            }
        }
    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            stat_inc(STAT_PACKETS_MALFORMED);
            return XDP_PASS;
        }

        struct lpm_v6_key key = { .prefixlen = 128 };
        __builtin_memcpy(key.addr, &ip6->saddr, 16);

        __u8 *blocked = bpf_map_lookup_elem(&blocklist_v6, &key);
        if (blocked && *blocked) {
            stat_inc(STAT_PACKETS_DROPPED);
            return XDP_DROP;
        }
    }

    stat_inc(STAT_PACKETS_PASSED);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
