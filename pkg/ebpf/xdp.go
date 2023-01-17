package ebpf

import (
	"fmt"
	"net"
	"os"
)

// XDP Contains the basic configuration for the generated XDP eBPF function
type XDP struct {
	Builder
	ctx               bool
	ethernet          bool
	ip                bool
	tcp               bool
	udp               bool
	returnVal         int
	DetectedInterface net.Interface
	postCode          string
	IPVariables       []xdpvars
	TCPVariables      []xdpvars
}

type xdpvars struct {
	varType string
	varName string
	name    string
}

// NewXDP Creates a new XDP eBFP object that will be eventually built into a bpf program
func NewXDP(name, license string, debug bool) (*XDP, error) {
	b := Builder{}
	b.Debug = debug
	b.symlink = "xdp.c"
	b.SetLicense(license)
	b.SetFunctionName(name)
	// Find default interface
	iface, _, err := GetNetConfig()
	if err != nil {
		return nil, err
	}
	x := XDP{Builder: b, DetectedInterface: iface}
	return &x, nil
}

// AppendCode will add code to the bottom of the function
func (x *XDP) AppendCode(code string) {
	x.postCode += "    " + code
}

// ParseContext will enable the code for parsing the eBPF context (ctx)
func (x *XDP) ParseContext() {
	x.ctx = true
}

// ParseEthernet will enable the code for parsing the Ethernet Frame (w/ dependancies)
func (x *XDP) ParseEthernet() {
	x.ParseContext()
	x.ethernet = true
}

// ParseIP will enable the code for parsing the IP Header (w/ dependancies)
func (x *XDP) ParseIP() {
	x.ParseContext()
	x.ParseEthernet()
	x.ip = true
}

// ParseTCP will enable the code for parsing the TCP Header (w/ dependancies)
func (x *XDP) ParseTCP() {
	x.ParseContext()
	x.ParseEthernet()
	x.ParseIP()
	x.tcp = true
}

// ParseUDP will enable the code for parsing the UDP Header (w/ dependancies)
func (x *XDP) ParseUDP() {
	x.ParseContext()
	x.ParseEthernet()
	x.ParseIP()
	x.udp = true
}

// Get source address through variable saddress
func (x *XDP) GetIPSourceAddress() {
	x.IPVariables = append(x.IPVariables, xdpvars{varType: "int", varName: "ip->saddr", name: "saddress"})
}

// Get destination port through variable dport
func (x *XDP) GetIPDestinationAddress() {
	x.IPVariables = append(x.IPVariables, xdpvars{varType: "int", varName: "ip->daddr", name: "daddress"})
}

// Get source port through variable sport
func (x *XDP) GetTCPSourcePort() {
	x.TCPVariables = append(x.TCPVariables, xdpvars{varType: "int", varName: "tcp->source", name: "sport"})
}

// Get destination port through variable dport
func (x *XDP) GetTCPDestinationPort() {
	x.TCPVariables = append(x.TCPVariables, xdpvars{varType: "int", varName: "tcp->dest", name: "dport"})
}

// This will generate actual eBPF code and associated wrappers, depends on GENERATE being set as an environment
// variable, if set to true will also print the go wrapper to STDOUT
func (x *XDP) Generate(printGo bool) error {
	if !x.Builder.written {
		err := x.Write()
		if err != nil {
			return err
		}
	}
	if printGo {
		fmt.Printf(xdpGoWrapper, x.name)

	}
	_, gen := os.LookupEnv("GENERATE")
	if gen {
		return x.Builder.Generate()
	}
	return nil
}

// This will generate actual eBPF code and associated wrappers, depends on GENERATE being set as an environment
// variable
func (x *XDP) Write() error {
	_, gen := os.LookupEnv("GENERATE")
	if gen {
		return x.Builder.Write()
	}
	return nil
}
