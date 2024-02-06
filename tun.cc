/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-09-16 22:40:00
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-02-05 14:34:57
 * @FilePath: \sslvpn-test\tun.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
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

        printf("tun config -> global: %d dev: %s, mtu: %d, ipv4: %s, ipv4_net: %s, ipv6: %s\n", tunCfg->global,
               tunCfg->dev, tunCfg->mtu, tunCfg->ipv4, tunCfg->ipv4_net, tunCfg->ipv6);

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

        // 设置了全局代理
        if (tunCfg->global)
        {
            memset(buf, 0, sizeof(buf));
            sprintf(buf, "route add -net 0.0.0.0/1 dev %s", tunCfg->dev);
            printf("shell run: %s\n", buf);
            system(buf);
            memset(buf, 0, sizeof(buf));
            sprintf(buf, "route add -net 128.0.0.0/1 dev %s", tunCfg->dev);
            printf("shell run: %s\n", buf);
            system(buf);
        }
        return 0;
    }

    int tun_create_mq(TUNCONFIG_T *tunCfg, int queues, int *fds)
    {
        struct ifreq ifr;
        int fd, err, i;

        if (!tunCfg || *tunCfg->dev == '\0')
        {
            return -1;
        }

        memset(&ifr, 0, sizeof(ifr));
        /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
         *        IFF_TAP   - TAP device
         *
         *        IFF_NO_PI - Do not provide packet information
         *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
         */
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
        strcpy(ifr.ifr_name, tunCfg->dev);

        for (i = 0; i < queues; i++)
        {
            if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
            {
                goto err;
            }
            err = ioctl(fd, TUNSETIFF, (void *)&ifr);
            if (err)
            {
                close(fd);
                goto err;
            }
            printf("alloc tun fd: %d\n", fd);
            fds[i] = fd;
        }

        config_tun(tunCfg);

        return 0;
    err:
        printf("tun_create_mq fail, err: %d\n", err);
        for (--i; i >= 0; i--)
        {
            close(fds[i]);
        }
        return err;
    }

    int tun_set_queue(int fd, int enable)
    {
        struct ifreq ifr;

        memset(&ifr, 0, sizeof(ifr));

        if (enable)
            ifr.ifr_flags = IFF_ATTACH_QUEUE;
        else
            ifr.ifr_flags = IFF_DETACH_QUEUE;

        return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
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