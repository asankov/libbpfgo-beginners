// +build ignore
#include "hello.bpf.h"

SEC("kprobe/sys_execve")
int hello(void *ctx)
{
    bpf_printk("Hello, Go");
    return 0;
}
