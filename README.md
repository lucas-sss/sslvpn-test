<!--
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-09-16 23:21:36
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2023-09-26 14:08:59
 * @FilePath: \sslvpn-test\README.md
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->
## 依赖项
- 铜锁ssl库，默认安装路径:/opt/tongsuo
- 铜锁编译参数如下：
```shell
./config --prefix=/opt/tongsuo enable-ntls --api=1.1.1
```

## 编译
```shell
mkdir build
cd build
cmake ..
make
```

## 运行

- 服务端
```shell
./sslvpn [port] #默认端口为1443
```

- linux 客户端
```shell
./sslvpn-client server_ip server_port
```

- windows 客户端

功能暂未实现，虚拟网卡读写可参考: [wintun](https://www.wintun.net/)


- 移动端
```text
无
```