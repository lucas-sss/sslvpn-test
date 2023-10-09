/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-10-09 11:06:59
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2023-10-09 18:15:48
 * @FilePath: \sslvpn-test\proxy.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <iostream>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

int connect_proxy(const char *server_addr, int server_port)
{
    int sockfd;
    struct sockaddr_in serveraddr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("create proxy socket fail\n");
        return -1;
    }

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(server_port);
    if (inet_aton(server_addr, (struct in_addr *)&serveraddr.sin_addr.s_addr) == 0)
    {
        printf("parse server addr fail\n");
        return -1;
    }

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) != 0)
    {
        printf("connect proxy server fail\n");
        return -1;
    }
    printf("create proxy socket fd: %d\n", sockfd);
    return sockfd;
}