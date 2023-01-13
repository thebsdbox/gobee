package ebpf

// XDP Contains the basic configuration for the generated XDP eBPF function
type XDP struct {
	Builder
	ctx       bool
	ethernet  bool
	ip        bool
	tcp       bool
	udp       bool
	returnVal int

	postCode     string
	IPVariables  []xdpvars
	TCPVariables []xdpvars
}

type xdpvars struct {
	varType string
	varName string
	name    string
}

// NewXDP Creates a new XDP eBFP object that will be eventually built into a bpf program
func NewXDP(license string, debug bool) *XDP {
	b := Builder{}
	b.Debug = debug
	b.symlink = "xdp.c"
	b.SetLicense(license)
	x := XDP{Builder: b}
	return &x
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
