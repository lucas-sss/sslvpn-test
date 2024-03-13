<!--
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-09-16 23:21:36
 * @LastEditors: liuwei lyy9645@163.com
 * @LastEditTime: 2024-03-13 23:14:38
 * @FilePath: \sslvpn-test\README.md
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->
## 依赖项
- 铜锁ssl库，默认安装路径:/opt/tongsuo，铜锁编译参数如下：
```shell
./config --prefix=/opt/tongsuo enable-ntls --api=1.1.1
```
- 编译时如果使用加密卡则依赖加密卡动态库（-DSDF=ON）libsdf_crypto.so

## 编译
```shell
mkdir build
cd build
cmake .. [-DSDF=ON] #添加-DSDF=ON指示编译engine时使用密码卡
make
```

## 运行
服务端客户端均可使用-h参数查看使用帮助

- linux服务端
```shell
sudo ./sslvpn [-p port] #默认端口为1443
```

- linux/macos 客户端
```shell
sudo ./sslvpn-client -s server_ip -p server_port
```

- windows 客户端

功能暂未实现，虚拟网卡读写可参考: [wintun](https://www.wintun.net/)


- 移动端
```text
无
```

## 注意事项

- macos环境下暂时未编译服务端