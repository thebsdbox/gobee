package ebpf

import (
	"fmt"
	"runtime"
)

// Build will create and start the eBPF code
func (x *XDP) Build() error {
	var codeBuilder string
	x.Builder.headers += xdpHeaders
	if x.ctx {
		codeBuilder += xdpContext
		if x.Builder.Debug {
			_, fname, fline, _ := runtime.Caller(0)
			codeBuilder += fmt.Sprintf("    // %s:%d\n", fname, fline)
		}
	}

	if x.ethernet {
		x.Builder.headers += xdpEthernetHeader
		codeBuilder += xdpEthernet
		if x.Builder.Debug {
			_, fname, fline, _ := runtime.Caller(0)
			codeBuilder += fmt.Sprintf("    // %s:%d\n", fname, fline)
		}
	}

	if x.ip {
		x.Builder.headers += xdpIPHeader
		codeBuilder += xdpCheckIP
		codeBuilder += xdpIP
		if x.Builder.Debug {
			_, fname, fline, _ := runtime.Caller(0)
			codeBuilder += fmt.Sprintf("    // %s:%d\n", fname, fline)
		}
	}

	if x.tcp {
		x.Builder.headers += xdpTCPHeader
		codeBuilder += xdpCheckTCP
		codeBuilder += xdpTCP
		if x.Builder.Debug {
			_, fname, fline, _ := runtime.Caller(0)
			codeBuilder += fmt.Sprintf("    // %s:%d\n", fname, fline)
		}
	}

	if len(x.postCode) != 0 {
		codeBuilder += x.postCode
		if x.Builder.Debug {
			_, fname, fline, _ := runtime.Caller(0)
			codeBuilder += fmt.Sprintf("    // %s:%d\n", fname, fline)
		}
	}
	x.Builder.code += fmt.Sprintf(xdpCode, codeBuilder)
	return x.Builder.Compile()
}
