package main

import (
	"log"

	"github.com/thebsdbox/ebpf/pkg/ebpf"
)

func main() {
	// Create a new XDP object (name, license, debugging)
	x, err := ebpf.NewXDP("Demo", "GPL", true)
	if err != nil {
		log.Fatalf("Error creating XDP object: %s", err)
	}
	// Enable TCP parsing (including adding headers)
	x.ParseTCP()

	// Get some variables!
	x.GetTCPDestinationPort()
	x.GetTCPSourcePort()
	x.GetIPDestinationAddress()
	x.GetIPSourceAddress()

	// Add some code
	x.AppendCode("bpf_printk(\"from %pI4, to %pI4:%d\", &saddress, &daddress, bpf_htons(dport));")

	// Create the code in-memory
	x.Create()

	// Generate the code/create the Go Wrappers, and if true create a Go snippet
	err = x.Generate(true)
	if err != nil {
		panic(err)
	}
}
