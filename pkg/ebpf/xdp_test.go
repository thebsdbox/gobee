package ebpf

import "testing"

func TestXDP_Build(t *testing.T) {

	x := NewXDP("GPL", true)
	x.ParseTCP()
	t.Run("Context", func(t *testing.T) {
		if err := x.Build(); (err != nil) != false {
			t.Errorf("XDP.Build() error = %v, wantErr %v", err, false)
		}
	})

}
