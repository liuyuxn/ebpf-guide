# eBPF Program Types · eBPF 程序类型

基于 Kernel Version 5.19。

eBPF 程序类型名在 `linux/bpf.h` 头文件的 `enum bpf_prog_type` 中定义。

> 「注」文中所有路径以本地目录 `/usr/include/` 为起始，其对应的是内核源码的 `/include/uapi/` 目录。

## Socket Related · 套接字相关

### SOCKET_FILTER

监测套接字上的网络包，并对网络包的副本进行一系列操作以获取信息。

+ eBPF 程序类型名：`BPF_PROG_TYPE_SOCKET_FILTER` 
+ Context 类型：`struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`socket`

### SOCK_OPS

description

+ eBPF 程序类型名：`BPF_PROG_TYPE_SOCK_OPS`
+ Context 类型：`` （定义在 ``）
+ 使用 libbpf 时的 ELF 文件 section 名：``

### SK_SKB

description

+ eBPF 程序类型名：`BPF_PROG_TYPE_SK_SKB`
+ Context 类型：`` （定义在 ``）
+ 使用 libbpf 时的 ELF 文件 section 名：``

## Traffic Control · 流控制

### tc_cls_act 

## XDP

### XDP

description

+ eBPF 程序类型名：`BPF_PROG_TYPE_XDP`
+ Context 类型：`` （定义在 ``）
+ 使用 libbpf 时的 ELF 文件 section 名：``

## Observerbility and Security · 可观测性和安全性

### KPROBE

### TRACEPOINT

### PERF_EVENT

## cgroups Related · cgroup 相关

### CGROUP_SKB

### CGROUP_SOCK

## Lightweight Tunnel

### LWT_IN

### LWT_OUT

### LWT_XMIT

## Others · 其它

### UNSPEC

### SCHED_CLS

### SCHED_ACT

### CGROUP_DEVICE

### SK_MSG

### RAW_TRACEPOINT

### CGROUP_SOCK_ADDR

### LWT_SEG6LOCAL

### LIRC_MODE2

### SK_REUSEPORT

### FLOW_DISSECTOR

### CGROUP_SYSCTL

### RAW_TRACEPOINT_WRITABLE

### CGROUP_SOCKOPT

### TRACING

### STRUCT_OPS

### EXT

### LSM

### SK_LOOKUP

### SYSCALL

## References · 参考

https://elixir.bootlin.com/linux/v5.19/source

https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types
