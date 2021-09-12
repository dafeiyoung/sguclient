# 潘多拉SDK编译固件

#### 1、准备环境

1. 首先装好 Ubuntu 64bit，推荐 Ubuntu 18 LTS x64
2. 命令行输入 `sudo apt-get update` ，然后输入 `sudo apt-get -y install build-essential asciidoc binutils bzip2 gawk gettext git libncurses5-dev libz-dev patch python3 python2.7 unzip zlib1g-dev lib32gcc1 libc6-dev-i386 subversion flex uglifyjs git-core gcc-multilib p7zip p7zip-full msmtp libssl-dev texinfo libglib2.0-dev xmlto qemu-utils upx libelf-dev autoconf automake libtool autopoint device-tree-compiler g++-multilib antlr3 gperf wget curl swig rsync help2man yui-compressor golang npm ocaml`
3. 下载潘多拉`PandoraBox-ImageBuilder`
4. 切换到PandoraBox-ImageBuilder下，用 `make info` 查看每款路由器对应的名字和PACKAGES
5. 编译的命令格式如下：

```shell
# netgear-r6220
make image PROFILE="netgear-r6220" PACKAGES="wget" FILES="files"
# 优酷路由宝
make image PROFILE="yk-l1" PACKAGES="sguclient"
# k2p
make image PROFILE="k2p" PACKAGES="sguclient"
```

这里说明一下后面几个参数的含义：
**PROFILE**: 这个参数的含义是路由器的型号，至于路由型号的写法去哪里找，目前资料都没有说，大家可以去看 Pandorabox 官方固件中路由器型号的名称，例如从 'PandoraBox-ralink-mt7621-netgear-r6220-2018-12-14-git-ba60306f2-squashfs-sysupgrade.bin' 中可以看到 PROFILE 是 netgear-r6220''。

**PACKAGES**: 这个参数的含义是支出你想编译的固件需要打包（如果有些插件你没有给出但是默认有的话也是会进行打包的，如果你想实现某些功能就去添加某些插件）

**不打包**（使用 '-插件名' 来表示）哪些插件，对于每种路由器的固件官方会给出一个默认的插件列表，可以在 'PandoraBox-ImageBuilder-ralink-mt7621.Linux-x86_64-2018-12-14-git-ba60306f2' 目录下使**用 'make info' 查看每款路由器对应的 PACKAGES。**

**FILES**: 查看其它的资料说会将该目录下的文件打包到固件当中，所以该参数配置的目录可以看做是固件的根目录，打包时会按照路径打包到固件对应的目录中，我目前没有这类需求，所以没有进行尝试。

比如：想每次编译出的固件 ip为：192.169.19.11 网关：192.168.19.254 掩码：255.255.255.0

新建目录PandoraBox-ImageBuilder/files/etc/config/network文本文件

编辑：

```shel
config interface 'wan'
	option ipaddr '192.168.19.11'
	option gateway '192.168.19.254'
	option netmask '255.255.255.0'
```



#### 2、编译中文翻译

1. 在进入tools文件下`sudo make install`

2. 在终端测试输入`po2lmo`，显示`Usage: po2lmo input.po output.lmo`即安装工具成功

3. 到sguclient/i18n/zh-cn下`po2lmo sguclient.zh-cn.lo sguclient.zh-cn.lmo`即可

4. 剩余makefile已写好无需修改

   > 参考[这个文章](https://blog.csdn.net/lvshaorong/article/details/54925266)技巧十四

