/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-03-02 22:30:42
 * @LastEditors: liuwei lyy9645@163.com
 * @LastEditTime: 2024-03-13 23:02:51
 * @FilePath: \sslvpn-test\engine\random.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
/**
 *
 * Created by liuwei@flksec.com on 09/01/2020.
 */
#include <openssl/rand.h>
#include <openssl/types.h>
#include <stdio.h>
#include <string.h>

#include "random.h"
#include "sdf.h"
#include "key.h"

#ifdef __cplusplus
extern "C"
{
#endif

    static int rand_seed(const void *s, int num)
    {
        return 1;
    }

    static int sdf_random_bytes(unsigned char *buf, int num)
    {
        printf("ENGINE -> sdf_random_bytes: num[%d]\n", num);

        int r;

        if (!buf || num > 1024 << 2)
        {
            return 0;
        }
#ifndef NO_SDF
        // 获取密码卡session
        SESSION_LINK *link;
        r = getSessionLink(&link);
        if (r)
        {
            printf("ENGINE -> getSessionLink: get sdf session fail, ret[%x]\n", r);
            return 0;
        }

        r = SDF_GenerateRandom(link->sessionHandle, num, buf);
        if (r)
        {
            printf("ENGINE -> sdf_random_bytes: flk_SDF_GenerateRandom failed, r[%x]\n", r);
            return 0;
        }
#else
        srand(time(NULL)); // 使用当前时间作为随机数种子
        // 生成16个随机无符号字符
        for (int i = 0; i < num; i++)
        {
            buf[i] = (unsigned char)(rand() % 256); // 生成0到255之间的随机数作为无符号字符
        }
#endif
        return 1;
    }

    static int random_status(void)
    {
        return 1;
    }

    static void random_cleanup(void)
    {
        // return 1;
    }

    const RAND_METHOD sdfRandMethod = {
        rand_seed,
        sdf_random_bytes,
        random_cleanup,
        NULL,
        sdf_random_bytes,
        random_status,
    };

    const RAND_METHOD *ssl_engine_rand()
    {
        return &sdfRandMethod;
    }
#ifdef __cplusplus
}
#endif