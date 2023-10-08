#include <iostream>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

int connect_proxy(char ip_addr, int port)
{
    // 创建一个socket
    int clientfd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientfd == -1)
    {
        cout << " create client socket error " << endl;
        return -1;
    }
    // 连接服务器
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = inet_addr(ip_addr);
    serveraddr.sin_port = port;
    if (connect(clientfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1)
    {
        cout << "connect socket error" << endl;
        return -1;
    }
    return clientfd;
}