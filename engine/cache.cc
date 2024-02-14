/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-02-06 16:20:35
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-02-14 09:36:09
 * @FilePath: \sslvpn-test\engine\sdfcache.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <stdio.h>
#include <string.h>

#include "cache.h"
#include "sdf.h"

#ifdef __cplusplus
extern "C"
{
#endif

    static void *devHandle;
    static void *sessionHandle;

    int sdfSessionInit()
    {
        int r = SDF_OpenDevice(&devHandle);
        if (r)
        {
            printf("SDF_OpenDevice failed.\n");
            return r;
        }
        r = SDF_OpenSession(devHandle, &sessionHandle);
        if (r)
        {
            printf("SDF_OpenSession failed.\n");
            return r;
        }
        return 0;
    }

    int sdfSessionDestory()
    {
        if (sessionHandle)
        {
            SDF_CloseSession(sessionHandle);
        }
        if (devHandle)
        {
            SDF_CloseDevice(devHandle);
        }
    }

    int getSdfSession(void **handle)
    {
        if (handle == NULL)
        {
            return -1;
        }
        *handle = sessionHandle;
        return 0;
    }

#ifdef __cplusplus
}
#endif