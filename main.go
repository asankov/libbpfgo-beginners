package main

import (
	"C"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
import (
	"fmt"
	"os"
	"os/signal"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	// load the BPF module from the file
	b, err := bpf.NewModuleFromFile("hello.bpf.o")
	must(err)
	// close the module on exit
	defer b.Close()

	// load the object from the module
	err = b.BPFLoadObject()
	must(err)

	// get the program from the module
	// "hello" is the name of the function in the C code
	p, err := b.GetProgram("hello")
	must(err)

	// attach the program to the execve kprobe
	_, err = p.AttachKprobe("__x64_sys_execve")
	must(err)

	// this function blocks and reads from the BPF stream
	// run it in a goroutine so that it does not block the main goroutine
	go bpf.TracePrint()

	// listen for the os.Interrupt signal
	// and block until it is send
	<-sig

	fmt.Println("Cleaning up")

}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
