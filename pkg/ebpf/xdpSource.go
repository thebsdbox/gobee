package ebpf

// Source Code headers

const xdpHeaders = `#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
`

const xdpEthernetHeader = `#include <linux/if_ether.h>
#include <linux/in.h>
`
const xdpIPHeader = `#include <linux/ip.h>
`
const xdpTCPHeader = `#include <linux/tcp.h>
`

// Function code
const xdpCode = `
SEC("xdp")
int  xdp_%s(struct xdp_md *ctx)
{
%s
}
`

// Parsing code
const xdpContext = `    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
`

const xdpEthernet = `    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
	    return XDP_PASS;
    }
`

const xdpCheckIP = `    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
	    // The protocol is not IPv4, so we can't parse an IPv4 source address.
	    return XDP_PASS;
    }
`

const xdpIP = `    // Then parse the IP header.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
	    return XDP_PASS;
    }
`

const xdpCheckTCP = `    if (ip->protocol != IPPROTO_TCP)
    {
	    return XDP_PASS;
	}
`

const xdpTCP = `    struct tcphdr *tcp = data + sizeof(struct ethhdr) + (ip->ihl * 4);
    if (tcp + 1 > (struct tcphdr *)data_end)
    {
	    return XDP_PASS;
    }
`

const xdpVar = `    %s %s = %s;
`

const xdpGoWrapper = `
// Load pre-compiled programs into the kernel.
objs := bpfObjects{}
if err := loadBpfObjects(&objs, nil); err != nil {
    log.Fatalf("loading objects: %%s", err)
}
defer objs.Close()

// Attach the program.
l, err := link.AttachXDP(link.XDPOptions{
    Program:   objs.Xdp%s,
    Interface: x.DetectedInterface.Index,
})
if err != nil {
    log.Fatalf("could not attach XDP program: %%s", err)
}
defer l.Close()

ebpf.Trace() // Blocking call that watches debug logs (ctrl+c to exit)
`
