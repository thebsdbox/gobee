package ebpf

import (
	"errors"
	"net"
	"os"
	"time"
)

func GetNetConfig() (net.Interface, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return net.Interface{}, "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return iface, ip.String(), nil
		}
	}
	return net.Interface{}, "", errors.New("are you connected to the network?")
}

func FailSafeTimeOut(t time.Duration, timeout func() error) {
	go func() {
		time.Sleep(t)
		timeout()
		os.Exit(1)
	}()
}
