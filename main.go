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

	// attach the program to the sys_enter tracepoint
	_, err = p.AttachRawTracepoint("sys_enter")
	must(err)

	// make a channel to which the events from the perf buffer will be send to
	events := make(chan []byte, 300)
	// attach the channel to the perf buffer in kernel-space
	// ignore all lost events
	pb, err := b.InitPerfBuf("map", events, nil, 1024)
	must(err)
	// start listenning for events from the perf buffer
	pb.Start()

	c := make(map[string]int)
	go func() {
		for {
			data := <-events
			comm := string(data)
			// fmt.Printf("Got %v\n", comm)
			c[comm]++
		}
	}()

	// listen for the os.Interrupt signal
	// and block until it is send
	<-sig

	fmt.Println("Cleaning up")
	pb.Stop()

	for k, v := range c {
		fmt.Printf("%s: %v\n", k, v)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
