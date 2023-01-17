package ebpf

import "testing"

func TestXDP_Build(t *testing.T) {

	x, _ := NewXDP("tst", "GPL", true)
	x.ParseTCP()
	x.GetTCPDestinationPort()
	x.GetTCPSourcePort()
	x.GetIPDestinationAddress()
	x.GetIPSourceAddress()
	x.AppendCode("bpf_printk(\"from %pI4, to %pI4\", saddress, daddress);")
	t.Run("Context", func(t *testing.T) {
		x.Create()
		if err := x.Write(); (err != nil) != false {
			t.Errorf("XDP.Build() error = %v, wantErr %v", err, false)
		}
	})

}
