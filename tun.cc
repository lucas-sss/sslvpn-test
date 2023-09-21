#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>

#include "tun.h"

#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * @brief 配置虚拟网卡
     *
     *
     * @param tunCfg
     * @return int
     */
    int config_tun(TUNCONFIG_T *tunCfg)
    {
        int ret = 0;
        char buf[512] = {0};
        char mtuStr[16] = {0};

        printf("tun config -> dev: %s, mtu: %d, ipv4: %s, ipv4_net: %s, ipv6: %s\n", tunCfg->dev,
               tunCfg->mtu, tunCfg->ipv4, tunCfg->ipv4_net, tunCfg->ipv6);

        // 设置mtu
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "ip link set dev %s mtu %d", tunCfg->dev, tunCfg->mtu);
        system(buf);

        // 设置ipv4地址
        if (strlen(tunCfg->ipv4) > 0)
        {
            memset(buf, 0, sizeof(buf));
            sprintf(buf, "ip addr add %s dev %s", tunCfg->ipv4, tunCfg->dev);
            printf("shell run: %s\n", buf);
            system(buf);
        }

        // 设置ipv6地址
        if (strlen(tunCfg->ipv6) > 0)
        {
            memset(buf, 0, sizeof(buf));
            sprintf(buf, "ip -6 addr add %s dev %s", tunCfg->ipv6, tunCfg->dev);
            printf("shell run: %s\n", buf);
            system(buf);
        }

        // 启动网卡
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "ip link set dev %s up", tunCfg->dev);
        printf("shell run: %s\n", buf);
        system(buf);

        // 设置路由
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "route add -net %s dev %s", tunCfg->ipv4_net, tunCfg->dev);
        printf("shell run: %s\n", buf);
        system(buf);

        return 0;
    }

    int tun_create(TUNCONFIG_T *tunCfg)
    {
        int flags = IFF_TUN | IFF_NO_PI;
        struct ifreq ifr;
        int fd, err;

        if ((fd = open("/dev/net/tun", O_RDWR)) < 0) //| O_NONBLOCK
        {
            printf("Tun device fd create error. (%d)\n", fd);
            return fd;
        }
        printf("create tun fd: %d\n", fd);

        memset(&ifr, 0, sizeof(struct ifreq));
        ifr.ifr_flags |= flags;
        if (*tunCfg->dev != '\0')
        {
            strcpy(ifr.ifr_name, tunCfg->dev);
        }
        if ((err = ioctl(fd, TUNSETIFF, &ifr)) < 0)
        {
            printf("Tun device ioctl configure error. (%d)\n", err);
            close(fd);
            return err;
        }
        printf("create tun device: %s\n", ifr.ifr_name);

        // 回显设置dev
        if (*tunCfg->dev == '\0')
        {
            strcpy(tunCfg->dev, ifr.ifr_name);
        }

        err = config_tun(tunCfg);
        if (err != 0)
        {
            printf("config tun fail");
        }
        return fd;
    }

#ifdef __cplusplus
}
#endif