package ebpf

import "testing"

// Example code taken from https://github.com/xdp-project/xdp-tutorial/blob/master/basic01-xdp-pass/xdp_pass_kern.c
const examplecode = `// +build ignore

/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
return XDP_PASS;
}
	
char _license[] SEC("license") = "GPL";`

func TestBuilder_Compile(t *testing.T) {

	type fields struct {
		code string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name:    "PASS CODE",
			fields:  fields{code: examplecode},
			wantErr: false,
		},
		{
			name:    "EMPTY CODE",
			fields:  fields{code: ""},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Builder{
				code: tt.fields.code,
			}
			if err := b.Compile(); (err != nil) != tt.wantErr {
				t.Errorf("Builder.Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
