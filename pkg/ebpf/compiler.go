package ebpf

import (
	"fmt"
	"os"
	"os/exec"
)

const ignore = `// +build ignore

`

// Compile will take the builder and turn it into some BPF code
func (b *Builder) Write() error {

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
