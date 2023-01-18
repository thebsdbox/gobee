package ebpf

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
)

const codeLicense = `char _license[] SEC("license") = "%s";`

// Builder contains everything required to build out our code
type Builder struct {
	name         string // Name of the eBPF function
	code         string // Holds the generated code
	removeSource bool   // Remove any source code at the end of generating
	license      string // Holds the license of the eBPF code
	headers      string // Keeps track of all headers required
	Debug        bool   // Adds debug comments
	written      bool   // Ensure we only need to write the code once
	maps         string
	filename     string // Filename of generated source
	symlink      string // symlink to latest version of generated source
}

// SetLicense will set the license for out BPF code
func (b *Builder) SetFunctionName(name string) {
	// Default to the GPL licence (TODO: Change this to something else)
	if name == "" {
		b.name = "example"
	} else {
		b.name = name
	}
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

func readLines(r io.Reader) {
	rd := bufio.NewReader(r)
	lineNum := 1
	for {
		line, err := rd.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s", line)

		lineNum++
	}
}

// Trace will start a blocking stream debugging data to STDOUT
func Trace() {
	file, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	readLines(file)
}
