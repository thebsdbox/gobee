package ebpf

import (
	"fmt"
	"runtime"
)

// Create will create the eBPF code
func (x *XDP) Create() error {
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
		if len(x.IPVariables) != 0 {
			for y := range x.TCPVariables {
				codeBuilder += fmt.Sprintf(xdpVar, x.IPVariables[y].varType, x.IPVariables[y].name, x.IPVariables[y].varName)
			}
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
		if len(x.TCPVariables) != 0 {
			for y := range x.TCPVariables {
				codeBuilder += fmt.Sprintf(xdpVar, x.TCPVariables[y].varType, x.TCPVariables[y].name, x.TCPVariables[y].varName)
			}
		}
	}

	if len(x.postCode) != 0 {
		codeBuilder += x.postCode
		if x.Builder.Debug {
			_, fname, fline, _ := runtime.Caller(0)
			codeBuilder += fmt.Sprintf("    // %s:%d\n", fname, fline)
		}
	}
	codeBuilder += "    return XDP_PASS;"

	x.Builder.code += fmt.Sprintf(xdpCode, codeBuilder)
	return x.Builder.Write()
}

