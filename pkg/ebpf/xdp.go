package ebpf

// XDP Contains the basic configuration for the generated XDP eBPF function
type XDP struct {
	Builder
	ctx      bool
	ethernet bool
	ip       bool
	tcp      bool
	udp      bool

	postCode string
}

// NewXDP Creates a new XDP eBFP object that will be eventually built into a bpf program
func NewXDP(license string, debug bool) *XDP {
	b := Builder{}
	b.Debug = debug
	b.SetLicense(license)
	x := XDP{Builder: b}
	return &x
}

// InsertCode will add code to the end of the function
func (x *XDP) InsertCode(code string) {
	x.postCode += code
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
