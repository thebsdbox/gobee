package ebpf

import "fmt"

const codeLicense = `char _license[] SEC("license") = "%s";`

//Builder contains everything required to build out our code
type Builder struct {
	code         string
	removeSource bool
	license      string
	headers      string // Keeps track of all headers required
	Debug        bool
}

//SetLicense will set the license for out BPF code
func (b *Builder) SetLicense(license string) {
	// Default to the GPL licence (TODO: Change this to something else)
	if license == "" {
		b.license = fmt.Sprintf(codeLicense, "GPL")
	} else {
		b.license = fmt.Sprintf(codeLicense, license)
	}
}
