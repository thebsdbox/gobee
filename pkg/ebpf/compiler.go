package ebpf

import (
	"fmt"
	"os"
	"os/exec"
)

const ignore = `// +build ignore

`

// Compile will take the builder and convert into C eBPF code
func (b *Builder) Write() error {
	if b.written {
		return nil
	} else {
		b.written = true
	}
	// Check code exists
	if len(b.code) == 0 {
		return fmt.Errorf("unable to compile eBPF as no code has been generated")
	}
	var builtCode string
	builtCode += ignore
	builtCode += b.headers
	builtCode += b.code
	builtCode += b.license

	// Create a temporary file to hold our source code before we compile it
	f, err := os.CreateTemp(".", "*.c")
	if err != nil {
		return err
	}
	if b.removeSource {
		// Remove the temporary files once compiled
		defer os.Remove(f.Name())
	} else {
		// Store the filename for later
		b.filename = f.Name()
		// remove the original symlink, to replace with a new one
		os.Remove(b.symlink)
		os.Symlink(b.filename, b.symlink)
	}

	// Write the code to file
	_, err = f.Write([]byte(builtCode))
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}

	return nil
}

func (b *Builder) Compile() error {
	var seq []string
	seq = append(seq, "-o2")             // Optimize produced code output
	seq = append(seq, "-g")              // Generate Debug output
	seq = append(seq, "-Wall")           // Enable Warnings for All
	seq = append(seq, "-target", "-bpf") // Output is bpf byte code
	seq = append(seq, "-c", b.filename)  // Input file
	seq = append(seq, "-o", "bpf.o")     // Output file

	// Compile the code into bpf code
	out, err := exec.Command("clang", seq...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot compile : %v\n%v", err, string(out))
	}
	return nil
}

func (b *Builder) Generate() error {
	var seq []string
	os.Setenv("GOPACKAGE", "main")
	seq = append(seq, "run")                               // Enable Warnings for All
	seq = append(seq, "github.com/cilium/ebpf/cmd/bpf2go") // Output is bpf byte code
	seq = append(seq, "bpf")                               // Input file
	seq = append(seq, b.symlink)                           // Output file

	// Compile the code into bpf code
	out, err := exec.Command("go", seq...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cannot compile : %v\n%v", err, string(out))
	}
	os.Exit(0)
	return nil
}
