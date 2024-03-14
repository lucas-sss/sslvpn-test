/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-09-16 22:40:00
 * @LastEditors: liuwei lyy9645@163.com
 * @LastEditTime: 2024-03-14 12:17:03
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
#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#elif __APPLE__
#include <net/if_utun.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#elif _WIN32
#else
#endif
#include <unistd.h>

#include "tun.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __APPLE__

    int utun_num(const char *dev)
    {
        char num[16] = {0};
        int i, j = 0;
        int len = 0;
        int v = 0;

        if (!dev)
        {
            return v;
        }
        len = strlen(dev);
        for (i = 0; i < len; i++)
        {
            if (dev[i] >= '0' && dev[i] <= '9')
            {
                num[j] = dev[i];
                j++;
                continue;
            }
        }

        v = atoi(num);
        if (v < 0)
        {
            v = 0;
        }
        else if (v > UINT8_MAX)
        {
            v = UINT8_MAX;
        }
        return v;
    }
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

#ifdef __linux__
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
#elif __APPLE__
        // 设置ipv4地址
        if (strlen(tunCfg->ipv4) > 0)
        {
            memset(buf, 0, sizeof(buf));
            // "ifconfig %s inet %s %s netmask %s up"
            sprintf(buf, "ifconfig %s inet %s %s up", tunCfg->dev, tunCfg->ipv4, tunCfg->gateway);
            printf("shell run: %s\n", buf);
            system(buf);
        }
        // TODO 设置ipv6地址

        // 设置mtu
        // memset(buf, 0, sizeof(buf));
        // sprintf(buf, "networksetup -setMTU %s mtu %d", tunCfg->dev, tunCfg->mtu);
        // printf("shell run: %s\n", buf);
        // system(buf);

        // 设置路由
        memset(buf, 0, sizeof(buf));
        sprintf(buf, "route add -net %s -interface %s", tunCfg->ipv4_net, tunCfg->dev);
        printf("shell run: %s\n", buf);
        system(buf);

        // // 设置了全局代理
        // if (tunCfg->global)
        // {
        //     memset(buf, 0, sizeof(buf));
        //     sprintf(buf, "route add -net 0.0.0.0/1 dev %s", tunCfg->dev);
        //     printf("shell run: %s\n", buf);
        //     system(buf);
        //     memset(buf, 0, sizeof(buf));
        //     sprintf(buf, "route add -net 128.0.0.0/1 dev %s", tunCfg->dev);
        //     printf("shell run: %s\n", buf);
        //     system(buf);
        // }
        return 0;
#elif _WIN32
        return -1;
#else
        return -1;
#endif
    }

    int tun_create_mq(TUNCONFIG_T *tunCfg, int queues, int *fds)
    {
#ifdef __linux__
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
#elif __APPLE__

#elif _WIN32
        return -1;
#else
        return -1;
#endif
    }

    int tun_set_queue(int fd, int enable)
    {
#ifdef __linux__
        struct ifreq ifr;

        memset(&ifr, 0, sizeof(ifr));

        if (enable)
            ifr.ifr_flags = IFF_ATTACH_QUEUE;
        else
            ifr.ifr_flags = IFF_DETACH_QUEUE;

        return ioctl(fd, TUNSETQUEUE, (void *)&ifr);
#elif __APPLE__

#elif _WIN32
        return -1;
#else
        return -1;
#endif
    }

    int tun_create(TUNCONFIG_T *tunCfg)
    {
#ifdef __linux__
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
#elif __APPLE__
        struct sockaddr_ctl sc = {0};
        struct ctl_info ctlInfo = {0};
        int fd;
        int num = 0;

        num = utun_num(tunCfg->dev);

        if (strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name)) >= sizeof(ctlInfo.ctl_name))
        {
            perror("UTUN_CONTROL_NAME too long");
            return -1;
        }

        if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1)
        {
            perror("socket(SYSPROTO_CONTROL)");
            return -1;
        }

        if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1)
        {
            perror("ioctl(CTLIOCGINFO");
            close(fd);
            return -1;
        }

        sc.sc_id = ctlInfo.ctl_id;
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;
        sc.sc_unit = num + 1; // just a example

        if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == -1)
        {
            perror("connect(AF_SYS_CONTROL");
            close(fd);
            return -1;
        }
        if (config_tun(tunCfg))
        {
            printf("macos config utun fail\n");
        }
        return fd;
#elif _WIN32
        return -1;
#else
        return -1;
#endif
    }

#ifdef __cplusplus
}
#endif