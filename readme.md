# 本项目是干什么的？

本项目旨在提供任何基于TCP协议的客户端与服务端程序之间的隧道服务。
编译本项目后可生成可执行文件**local**和**remote**：

  1. local为隧道服务客户端，负责接入被代理的客户端，然后将从被代理客户端接收到数据转发到remote
  2. remote为隧道服务服务端，负责从local接收数据，然后转发给被代理服务端

具体的数据交互示意图如下：

![](https://raw.githubusercontent.com/ruleless/tunnel/master/doc/tunnel.png)

# 可以用来干什么？
