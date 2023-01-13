package ebpf

import "testing"

func TestXDP_Build(t *testing.T) {

	x := NewXDP("GPL", true)
	x.ParseTCP()
	x.GetTCPDestinationPort()
	x.GetTCPSourcePort()
	x.GetIPDestinationAddress()
	x.GetIPSourceAddress()
	x.AppendCode("bpf_printk(\"from %pI4, to %pI4\", saddress, daddress);")
	t.Run("Context", func(t *testing.T) {
		if err := x.Create(); (err != nil) != false {
			t.Errorf("XDP.Build() error = %v, wantErr %v", err, false)
		}
	})

}
