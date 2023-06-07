# Compiling 编译
    
## Environment 环境

在 amd64 架构虚拟机中使用 Ubuntu 22.04.2 LTS (Jammy Jellyfish) 操作系统，Linux Kernel 版本 5.19。使用命令检查如下：

```
$ uname -a
Linux hostname 5.19.0-43-generic #44~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Mon May 22 13:39:36 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

## Dependencis 依赖

安装 git, clang, llvm, libelf1, libelf-dev, zlib1g-dev, binutils-dev, libcap-dev, gcc-multilib：

```
$ apt install git clang llvm libelf1 libelf-dev zlib1g-dev binutils-dev libcap-dev gcc-multilib
```

*「注」即使没有使用命令安装 zlib1g-dev，其也应作为依赖被自动安装。文中的部分命令执行可能需要 root 权限，以下不再注明。*

出于方便和较新的版本的原因，使用源码安装 bpftool 和 libbpf。

选择一个合适的目录，执行以下命令，以安装 bpftool：

```
$ git clone --depth=1 --recurse-submodules https://github.com/libbpf/bpftool.git
$ cd bpftool/src
$ make install
```

选择一个合适的目录，执行以下命令，以安装 libbpf：

```
$ git clone --depth=1 --branch v1.2.0 https://github.com/libbpf/libbpf.git
$ cd libbpf/src/
$ make install
```

## Hello World

下面给出一个 Hello World 样例。

新建 2 个文档，内容分别如下：

+ `hello.bpf.c`:

``` c
// hello.bpf.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int handle(void* ctx)
{
	bpf_printk("Hello, world!\n");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

+ `hello.c`:

``` c
// hello.c

#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"

int main()
{
	struct hello_bpf* skel;
	int err;

	skel = hello_bpf__open_and_load();
	err = hello_bpf__attach(skel);

	fprintf(stderr, "using command 'cat /sys/kernel/debug/tracing/trace_pipe' to get output\n");
	while(true)
	{
		sleep(1);
	}

	return -err;
}
```

在文档所在目录执行以下命令：

```
$ clang -target bpf -O2 -g -c -o hello.bpf.o hello.bpf.c
$ bpftool gen skeleton hello.bpf.o > hello.skel.h
$ clang hello.c -l:libbpf.a -lelf -lz -o hello
```

如果一切正常，将会在目录下得到可执行文件 `hello`。

执行 `hello`：

```
$ ./hello
```

可以在 `/sys/kernel/debug/tracing/trace_pipe` 文件中得到持续输出。
