// +build ignore
#include "hello.bpf.h"

SEC("kprobe/sys_execve")
int hello(void *ctx)
{
    // write some data to some well-known location
    // this function is useful only for debugging
    // if used in production can conflict with other
    // ebpf programs writing to the same pipe
    bpf_printk("Hello, Go");
    return 0;
}
