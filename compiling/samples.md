# 获取 Kernel Source，并生成 Sample 程序

**首先，请确认已经完成 Comiling 部分的 Environment 小节和 Dependencies 小节的工作。**

## 获取 Kernel Source

下面使用 apt 程序获取 Linux Kernel Source。

首先，修改源列表文件，将 `/etc/apt/source.list` 文件中所有以 `deb-src` 开头的行取消注释。

然后，更新包列表信息：

```
$ apt update
```

> *「注」文中部分命令可能需要管理员权限。*

接下来，安装 dpkg-dev：

```
$ apt install dpkg-dev
```

然后，执行以下命令将 Kernel Source 下载至当前目录：

```
$ apt source linux-image-unsigned-$(uname -r)
```

将获取到的包含 Kernel Source 的目录重命名为 `kernel-src`。

如果下载的源码的文件所有者不是当前用户，可以使用 `chown` 命令修改文件所有者，这可以简化后续的操作。

## 生成 Sample 程序

首先安装 flex 和 bison：

```
$ apt install flex bison
```

然后，执行一些必要的操作：

```
$ cd kernel-src
$ make defconfig
$ make headers_install
$ make prepare
```

接下来可以执行以下命令以生成 Sample 程序：

```
$ cd samples/bpf
$ make VMLINUX_BTF=/sys/kernel/btf/vmlinux
```

> *「注」尚不清楚上条指令中所指定的 `VMLINUX_BTF` 参数是否合理。*

如果一切顺利，应该在当前目录下得到了已经生成好的可执行程序。

## References 参考

https://www.kernel.org/doc/readme/samples-bpf-README.rst
