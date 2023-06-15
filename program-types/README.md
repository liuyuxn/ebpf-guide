# eBPF Program Types · eBPF 程序类型

基于 Kernel Version 5.19。

eBPF 程序类型名在 `linux/bpf.h` 头文件的 `enum bpf_prog_type` 中定义。

> *「注」文中所有相对路径以本地目录 `/usr/include/` 为起始，其对应的是内核源码的 `/include/uapi/` 目录。*

### CGROUP_DEVICE

+ eBPF 程序类型名：`BPF_PROG_TYPE_CGROUP_DEVICE`
+ Context 类型：极大概率是 `struct bpf_cgroup_dev_ctx *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`cgroup/dev`

### CGROUP_SKB

+ eBPF 程序类型名：`BPF_PROG_TYPE_CGROUP_SKB`
+ Context 类型：极大概率是 `struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`cgroup/skb`、`cgroup_skb/egress`、`cgroup_skb/ingress`

### CGROUP_SOCKOPT

+ eBPF 程序类型名：`BPF_PROG_TYPE_CGROUP_SOCKOPT`
+ Context 类型：极大概率是 `struct bpf_sockopt *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`cgroup/getsockopt`、`cgroup/setsockopt`

### CGROUP_SOCK_ADDR

+ eBPF 程序类型名：`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`
+ Context 类型：极大概率是 `struct bpf_sock_addr *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`cgroup/bind4`、`cgroup/connect4`、`cgroup/getpeername4`、`cgroup/getsockname4`、`cgroup/bind6`、`cgroup/connect6`、`cgroup/getpeername6`、`cgroup/getsockname6`、`cgroup/recvmsg4`、`cgroup/sendmsg4`、`cgroup/recvmsg6`、`cgroup/sendmsg6`

### CGROUP_SOCK

+ eBPF 程序类型名：`BPF_PROG_TYPE_CGROUP_SOCK`
+ Context 类型：极大概率是 `struct bpf_sock *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`cgroup/post_bind4`、`cgroup/post_bind6`、`cgroup/sock_create`、`cgroup/sock`、`cgroup/sock_release`

### CGROUP_SYSCTL

+ eBPF 程序类型名：`BPF_PROG_TYPE_CGROUP_SYSCTL`
+ Context 类型：极大概率是 `struct bpf_sysctl *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`cgroup/sysctl`

### EXT

+ eBPF 程序类型名：`BPF_PROG_TYPE_EXT`
+ Context 类型：似因具体的 ext 种类不同而异
+ 使用 libbpf 时的 ELF 文件 section 名：`freplace+`

> *「注」`type+` means it can be either exact `SEC("type")` or well-formed `SEC("type/extras")` with a ‘`/`’ separator between `type` and `extras`.*

### FLOW_DISSECTOR

+ eBPF 程序类型名：`BPF_PROG_TYPE_FLOW_DISSECTOR`
+ Context 类型：极大概率是 `struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`flow_dissector`

### KPROBE

+ eBPF 程序类型名：`BPF_PROG_TYPE_KPROBE`
+ Context 类型：`struct pt_regs *` （定义在多个体系结构相关的头文件中，绝大多数位于内核源码 `/arch/` 目录下）
+ 使用 libbpf 时的 ELF 文件 section 名：`kprobe+`、`kretprobe+`、`ksyscall+`、`kretsyscall+`、`uprobe+`、`uprobe.s+`、`uretprobe+`、`uretprobe.s+`、`usdt+`、`kprobe.multi+`、`kretprobe.multi+`

### LIRC_MODE2

+ eBPF 程序类型名：`BPF_PROG_TYPE_LIRC_MODE2`
+ Context 类型：极大概率是 `unsigned int *sample` 
+ 使用 libbpf 时的 ELF 文件 section 名：`lirc_mode2`

### LSM

+ eBPF 程序类型名：`BPF_PROG_TYPE_LSM`
+ Context 类型：似因具体的 lsm 种类不同而异
+ 使用 libbpf 时的 ELF 文件 section 名：`lsm_cgroup+`、`lsm+`、`lsm.s+`

### LWT_IN

+ eBPF 程序类型名：`BPF_PROG_TYPE_LWT_IN`
+ Context 类型：极大概率是 `struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`lwt_in`

### LWT_OUT

+ eBPF 程序类型名：`BPF_PROG_TYPE_LWT_OUT`
+ Context 类型：`struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`lwt_out`

### LWT_SEG6LOCAL

+ eBPF 程序类型名：`BPF_PROG_TYPE_LWT_SEG6LOCAL`
+ Context 类型：极大概率是 `struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`lwt_seg6local`

### LWT_XMIT

+ eBPF 程序类型名：`BPF_PROG_TYPE_LWT_XMIT`
+ Context 类型：`struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`lwt_xmit`

### PERF_EVENT

+ eBPF 程序类型名：`BPF_PROG_TYPE_PERF_EVENT`
+ Context 类型：`struct bpf_perf_event_data *` （定义在 `linux/bpf_perf_event.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`perf_event`

### RAW_TRACEPOINT_WRITABLE

+ eBPF 程序类型名：`BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE`
+ Context 类型：似因具体的 tracepoint 种类不同而异
+ 使用 libbpf 时的 ELF 文件 section 名：`raw_tp.w+`、`raw_tracepoint.w+`

### RAW_TRACEPOINT

+ eBPF 程序类型名：`BPF_PROG_TYPE_RAW_TRACEPOINT`
+ Context 类型：极大概率是 `struct bpf_raw_tracepoint_args *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`raw_tp+`、`raw_tracepoint+`

### SCHED_ACT

+ eBPF 程序类型名：`BPF_PROG_TYPE_SCHED_ACT`
+ Context 类型：极大概率是 `struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`action`

### SCHED_CLS

+ eBPF 程序类型名：`BPF_PROG_TYPE_SCHED_CLS`
+ Context 类型：极大概率是 `struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`classifier`、`tc`

### SK_LOOKUP

+ eBPF 程序类型名：`BPF_PROG_TYPE_SK_LOOKUP`
+ Context 类型：极大概率是 `struct bpf_sk_lookup *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`sk_lookup`

### SK_MSG

+ eBPF 程序类型名：`BPF_PROG_TYPE_SK_MSG`
+ Context 类型：极大概率是 `struct sk_msg_md *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`sk_msg`

### SK_REUSEPORT

+ eBPF 程序类型名：`BPF_PROG_TYPE_SK_REUSEPORT`
+ Context 类型：极大概率是 `struct sk_reuseport_md *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`sk_reuseport/migrate`、`sk_reuseport`

### SK_SKB

+ eBPF 程序类型名：`BPF_PROG_TYPE_SK_SKB`
+ Context 类型：`struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`sk_skb`、`sk_skb/stream_parser`、`sk_skb/stream_verdict`

### SOCKET_FILTER

监测套接字上的网络包，并对网络包的副本进行一系列操作以获取信息。

+ eBPF 程序类型名：`BPF_PROG_TYPE_SOCKET_FILTER` 
+ Context 类型：`struct __sk_buff *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`socket`

### SOCK_OPS

+ eBPF 程序类型名：`BPF_PROG_TYPE_SOCK_OPS`
+ Context 类型：`struct bpf_sock_ops *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`sockops`

### STRUCT_OPS

+ eBPF 程序类型名：`BPF_PROG_TYPE_STRUCT_OPS`
+ Context 类型：似因具体的 struct_ops 种类不同而异
+ 使用 libbpf 时的 ELF 文件 section 名：`struct_ops+`

### SYSCALL

+ eBPF 程序类型名：`BPF_PROG_TYPE_SYSCALL`
+ Context 类型：可能有多种不同的类型
+ 使用 libbpf 时的 ELF 文件 section 名：`syscall`

### TRACEPOINT

+ eBPF 程序类型名：`BPF_PROG_TYPE_TRACEPOINT`
+ Context 类型：因不同的 tracepoint 类型而异（可以在 `/sys/kernel/tracing/events` 目录下查询）
+ 使用 libbpf 时的 ELF 文件 section 名：`tp+`、`tracepoint+`

### TRACING

+ eBPF 程序类型名：`BPF_PROG_TYPE_TRACING`
+ Context 类型：似因具体的 tracing 种类不同而异
+ 使用 libbpf 时的 ELF 文件 section 名：`fmod_ret+`、`fmod_ret.s+`、`fentry+`、`fentry.s+`、`fexit+`、`fexit.s+`、`iter+`、`iter.s+`、`tp_btf+`

### XDP

+ eBPF 程序类型名：`BPF_PROG_TYPE_XDP`
+ Context 类型：`struct xdp_md *` （定义在 `linux/bpf.h`）
+ 使用 libbpf 时的 ELF 文件 section 名：`xdp.frags/cpumap`、`xdp/cpumap`、`xdp.frags/devmap`、`xdp/devmap`、`xdp.frags`、`xdp`

### UNSPEC

无效类型
+ eBPF 程序类型名：`BPF_PROG_TYPE_UNSPEC`

### tc_cls_act 

参见 `iproute2` 代码
+ Context 类型：`struct __sk_buff *`（定义在 `linux/bpf.h`）

## References · 参考

https://elixir.bootlin.com/linux/v5.19/source

https://libbpf.readthedocs.io/en/latest/program_types.html

https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types
