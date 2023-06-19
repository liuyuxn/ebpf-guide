# BTF Data for Maps · Map 的 BTF 数据

在包含 eBPF 程序的 ELF 文件中，BTF 信息详细记录了程序中所定义的 map 的信息。

以 Linux 的 Sample 程序 `xdp1_kern.c` 为例，介绍如何利用 BTF 数据解读 map 信息。

## Print BTF with bpftool · 使用 bpftool 程序打印 BTF

按照说明生成 Linux 的 Sample 程序后，在文件夹中得到 `xdp1_kern.o` 文件。

执行以下命令可以打印 `xdp1_kern.o` 文件中的 BTF 信息：

```
bpftool btf dump file xdp1_kern.o
```

> *「注」文中的部分命令执行可能需要管理员权限，以下不再注明。*

输出的 BTF 信息如下：

```
[1] PTR '(anon)' type_id=3
[2] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
[3] ARRAY '(anon)' type_id=2 index_type_id=4 nr_elems=6
[4] INT '__ARRAY_SIZE_TYPE__' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[5] PTR '(anon)' type_id=6
[6] TYPEDEF 'u32' type_id=7
[7] TYPEDEF '__u32' type_id=8
[8] INT 'unsigned int' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[9] PTR '(anon)' type_id=10
[10] INT 'long' size=8 bits_offset=0 nr_bits=64 encoding=SIGNED
[11] PTR '(anon)' type_id=12
[12] ARRAY '(anon)' type_id=2 index_type_id=4 nr_elems=256
[13] STRUCT '(anon)' size=32 vlen=4
	'type' type_id=1 bits_offset=0
	'key' type_id=5 bits_offset=64
	'value' type_id=9 bits_offset=128
	'max_entries' type_id=11 bits_offset=192
[14] VAR 'rxcnt' type_id=13, linkage=global
[15] PTR '(anon)' type_id=16
[16] STRUCT 'xdp_md' size=24 vlen=6
	'data' type_id=7 bits_offset=0
	'data_end' type_id=7 bits_offset=32
	'data_meta' type_id=7 bits_offset=64
	'ingress_ifindex' type_id=7 bits_offset=96
	'rx_queue_index' type_id=7 bits_offset=128
	'egress_ifindex' type_id=7 bits_offset=160
[17] FUNC_PROTO '(anon)' ret_type_id=2 vlen=1
	'ctx' type_id=15
[18] FUNC 'xdp_prog1' type_id=17 linkage=global
[19] INT 'char' size=1 bits_offset=0 nr_bits=8 encoding=SIGNED
[20] ARRAY '(anon)' type_id=19 index_type_id=4 nr_elems=4
[21] VAR '_license' type_id=20, linkage=global
[22] DATASEC '.maps' size=0 vlen=1
	type_id=14 offset=0 size=32 (VAR 'rxcnt')
[23] DATASEC 'license' size=0 vlen=1
	type_id=21 offset=0 size=4 (VAR '_license')
```

下面分析 map 的详细信息。

+ **Type 22**
  
  注意到编号 22 的类型名字是 `.maps`，这代表一个名为 `.maps` 的 ELF 节。节中有一行数据，其 `type_id` 是 14。

+ **Type 14**

  `Type 14` 名字是 `rxcnt`，其是对 `Type 13` 的定义。至此，我们知道了 map 的名字是 `rxcnt`。

+ **Type 13**

  `Type 13` 是一个 `STRUCT` 类型，其定义了 map 相关的信息。首先看第一行，名字是 `type`，其 `type_id` 是 1。这一行指出了 map 的类型。

+ **Type 1**

  `Type 1` 是一个指向 `Type 3` 的指针。

+ **Type 3**

  `Type 3` 是一个数组，这里只关心其 `nr_elems` 属性的值为 6。通过查询 `linux/bpf.h` 文件中的枚举类型 `enum bpf_map_type`，其编号为 6 的条目是 `BPF_MAP_TYPE_PERCPU_ARRAY`。至此，我们知道了 map 的类型是 `BPF_MAP_TYPE_PERCPU_ARRAY`。

通过分析 `Type 13` 的另外第 2 至 4 行，我们可以得到 map 的 key 类型是 `u32`，value 类型是 `long`，最大条目数量是 256。

对比 `xdp1_kern.c` 文件中的 map 定义，可以印证上述分析：

``` c
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __type(key, u32);
        __type(value, long);
        __uint(max_entries, 256);
} rxcnt SEC(".maps");
```

## Understanding BTF · BTF 解读

阅读 Kernel 文档可以获取各种 BTF 类型的详细信息：

https://docs.kernel.org/bpf/btf.html

## References · 参考

https://docs.kernel.org/bpf/btf.html

Learning eBPF by Liz Rice
