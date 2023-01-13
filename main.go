package main

import "github.com/thebsdbox/ebpf/pkg/ebpf"

func main() {
	x := ebpf.NewXDP("GPL", true)
	x.ParseTCP()
	x.GetTCPDestinationPort()
	x.GetIPDestinationAddress()
	x.GetIPSourceAddress()
	x.AppendCode("bpf_printk(\"from %pI4, to %pI4:%d\", saddress, daddress, dport);")
	x.Create()
}
