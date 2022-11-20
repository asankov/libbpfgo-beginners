// +build ignore
#include "hello.bpf.h"

// define a perf buffer named "map"
// we can use this map in the code below to send data to it
// and later in the userspace code
// this will prevent any conflicts with other eBPF programs
// running on the same machine
BPF_PERF_OUTPUT(map)
SEC("raw_tracepoint/sys_enter")
int hello(void *ctx)
{
    char data[30];
    bpf_get_current_comm(data, sizeof(data));
    bpf_perf_event_output(ctx, &map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}