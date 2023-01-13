package ebpf

import (
	"fmt"
)

const codeLicense = `char _license[] SEC("license") = "%s";`

// Builder contains everything required to build out our code
type Builder struct {
	code         string
	removeSource bool
	license      string
	headers      string // Keeps track of all headers required
	Debug        bool
	maps         string
	filename     string
	symlink      string
}

// SetLicense will set the license for out BPF code
func (b *Builder) SetLicense(license string) {
	// Default to the GPL licence (TODO: Change this to something else)
	if license == "" {
		b.license = fmt.Sprintf(codeLicense, "GPL")
	} else {
		b.license = fmt.Sprintf(codeLicense, license)
	}
}

// BPF_MAP_TYPE_ARRAY
const eBPFMap = `struct {
    __uint(type, %s);
    __type(key, %s);
    __type(value, %s);
    __uint(max_entries, %s);
} %s SEC(".maps");

`

// func (b *Builder) Runner() error {
// 	file, err := os.Open("bpf.o")
// 	if err != nil {
// 		return err
// 	}
// 	spec, err := ebpf.LoadCollectionSpecFromReader(file)
// 	if err != nil {
// 		return fmt.Errorf("can't load bpf: %w", err)
// 	}
// 	///objs := bpfObjects{}
// 	//spec.LoadAndAssign()
// }
