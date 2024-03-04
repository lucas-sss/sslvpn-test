/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-02-06 16:20:35
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-03-02 21:57:26
 * @FilePath: \sslvpn-test\engine\sdfcache.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "key.h"
#include "sdf.h"

#ifdef __cplusplus
extern "C"
{
#endif

    static pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;
    SESSION_LINK *sessionLink = NULL;
    KEY_LINK *keyLink = NULL;

    static int initSessionLink(SESSION_LINK *link, int threadId);
    static int initKeyLink(KEY_LINK *link, unsigned char *key, int threadId);

#ifndef NO_SDF
    int sdfSessionInit()
    {
        printf("ENGINE -> sdfSessionInit\n");
        // 初始化sessionLink
        sessionLink = (SESSION_LINK *)calloc(1, sizeof(SESSION_LINK));
        if (!sessionLink)
        {
            return -1;
        }
        memset(sessionLink, 0, sizeof(SESSION_LINK));
        if (initSessionLink(sessionLink, pthread_self()))
        {
            return -1;
        }

        // 初始化keyLink
        keyLink = (KEY_LINK *)calloc(1, sizeof(KEY_LINK));
        if (!keyLink)
        {
            return -1;
        }
        memset(keyLink, 0, sizeof(KEY_LINK));
        initKeyLink(keyLink, NULL, -1);

        return 0;
    }

    int sdfSessionDestory()
    {
        int r;
        // 销毁key
        KEY_LINK *temp = keyLink->next;
        while (temp)
        {
            if (temp->session->sessionHandle)
            {
                r = SDF_DestroyKey(temp->session->sessionHandle, temp->keyHandle);
                if (r)
                {
                    printf("SDF_DestroyKey failed, ret: %x\n", r);
                }
            }
            temp = temp->next;
        }
        // 关闭session
        SESSION_LINK *tempSessionLink = sessionLink;
        while (tempSessionLink)
        {
            r = SDF_CloseSession(tempSessionLink->sessionHandle);
            if (r)
            {
                printf("SDF_CloseSession failed, ret: %x\n", r);
            }
            r = SDF_CloseDevice(tempSessionLink->devHandle);
            if (r)
            {
                printf("SDF_CloseDevice failed, ret: %x\n", r);
            }
            tempSessionLink = tempSessionLink->next;
        }
        printf("ENGINE -> sdfSessionDestory finish\n");
    }

    static int initSessionLink(SESSION_LINK *link, int threadId)
    {
        printf("initSessionLink -> threadId: %d\n", threadId);
        link->next = NULL;
        link->devHandle = NULL;
        link->sessionHandle = NULL;
        link->threadid = threadId;

        // 打开设备
        int r = SDF_OpenDevice(&link->devHandle);
        if (r)
        {
            printf("SDF_OpenDevice failed.\n");
            return r;
        }
        printf("SDF_OpenDevice: %p\n", link->devHandle);
        // 打开会话
        r = SDF_OpenSession(link->devHandle, &link->sessionHandle);
        if (r)
        {
            printf("SDF_OpenSession failed.\n");
            return r;
        }
        return 0;
    }

    int getSessionLink(SESSION_LINK **link)
    {
        int threadId = pthread_self();

        // 查询session
        SESSION_LINK *temp = sessionLink;
        while (temp)
        {
            if (threadId == temp->threadid)
            {
                break;
            }
            temp = temp->next;
        }
        if (!temp)
        {
            printf("initKeyLink -> create new sdf session, threadid: %d\n", threadId);
            temp = (SESSION_LINK *)calloc(1, sizeof(SESSION_LINK));
            if (!temp)
            {
                return -1;
            }
            if (initSessionLink(temp, threadId))
            {
                printf("initKeyLink -> init sdf session fail, threadid: %d\n", threadId);
                return -1;
            }
            pthread_mutex_lock(&gMutex); // 加锁
            temp->next = sessionLink->next;
            sessionLink->next = temp;
            pthread_mutex_unlock(&gMutex); // 解锁
        }
        *link = temp;
        return 0;
    }

    static int initKeyLink(KEY_LINK *link, unsigned char *key, int threadId)
    {
        printf("initKeyLink -> threadId: %d\n", threadId);

        int r;

        link->next = NULL;
        link->keyHandle = NULL;

        if (key)
        {
            // 查询session
            // SESSION_LINK *temp = sessionLink;
            // while (temp)
            // {
            //     if (threadId == temp->threadid)
            //     {
            //         break;
            //     }
            //     temp = temp->next;
            // }
            // if (!temp)
            // {
            //     printf("initKeyLink -> not find session, threadid: %d\n", threadId);
            //     temp = (SESSION_LINK *)calloc(1, sizeof(SESSION_LINK));
            //     if (!temp)
            //     {
            //         return -1;
            //     }
            //     if (initSessionLink(temp, threadId))
            //     {
            //         return -1;
            //     }
            //     pthread_mutex_lock(&gMutex); // 加锁
            //     temp->next = sessionLink->next;
            //     sessionLink->next = temp;
            //     pthread_mutex_unlock(&gMutex); // 解锁
            // }

            SESSION_LINK *temp = NULL;
            if (getSessionLink(&temp) != 0)
            {
                return -1;
            }
            link->session = temp;

            r = SDF_ImportKey(temp->sessionHandle, key, 16, &link->keyHandle);
            if (r)
            {
                printf("SDF_ImportKey fail, ret: %x\n", r);
                return r;
            }
            printf("SDF_ImportKey: %p\n", link->keyHandle);
            memcpy(link->key, key, 16);
        }
        return 0;
    }

    int getKeyLink(KEY_LINK **link, unsigned char *key)
    {
        int r;
        int threadid = pthread_self();
        // printf("getKeyLink -> threadid: %d\n", threadid);

        KEY_LINK *temp = keyLink->next;
        while (temp)
        {
            if (memcmp(temp->key, key, 16) == 0)
            {
                break;
            }
            temp = temp->next;
        }
        if (!temp)
        {
            // printf("getKeyLink -> not find keyLink, threadid: %d\n", threadid);
            temp = (KEY_LINK *)calloc(1, sizeof(KEY_LINK));
            if (!temp)
            {
                return -1;
            }
            if (initKeyLink(temp, key, threadid))
            {
                return -1;
            }
            pthread_mutex_lock(&gMutex); // 加锁
            temp->next = keyLink->next;
            keyLink->next = temp;
            pthread_mutex_unlock(&gMutex); // 解锁
        }
        *link = temp;
        return 0;
    }
#endif

#ifdef __cplusplus
}
#endif