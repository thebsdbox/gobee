package main

import (
	"log"

	"github.com/thebsdbox/ebpf/pkg/ebpf"
)

func main() {
	x, err := ebpf.NewXDP("Demo", "GPL", true)
	if err != nil {
		log.Fatalf("Error creating XDP object: %s", err)
	}
	x.ParseTCP()
	x.GetTCPDestinationPort()
	x.GetTCPSourcePort()
	x.GetIPDestinationAddress()
	x.GetIPSourceAddress()
	x.AppendCode("bpf_printk(\"from %pI4, to %pI4:%d\", &saddress, &daddress, bpf_htons(dport));")
	x.Create()

	err = x.Generate(true)
	if err != nil {
		panic(err)
	}
}
