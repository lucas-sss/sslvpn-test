/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-02-06 16:20:35
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-04-06 13:34:34
 * @FilePath: \sslvpn-test\engine\sdfcache.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include "sdf_handler.h"
#include "sdf.h"

#ifdef __cplusplus
extern "C"
{
#endif

    static pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;
    void *globalDevHandle = NULL;
    SESSION_LINK *sessionLink = NULL;
    KEY_LINK *keyLink = NULL;
    volatile int keyNum = 0;

    static int initSessionLink(SESSION_LINK *link, long threadId);
    static int initKeyLink(KEY_LINK *link, unsigned char *key, long threadId);
    void clearEarlyKey();
    long getTimeSecond();

#ifndef NO_SDF
    int sdfSessionInit()
    {
        printf("ENGINE -> sdfSessionInit\n");
        // // 初始化sessionLink
        // sessionLink = (SESSION_LINK *)calloc(1, sizeof(SESSION_LINK));
        // if (!sessionLink)
        // {
        //     return -1;
        // }
        // memset(sessionLink, 0, sizeof(SESSION_LINK));

        // 打开设备
        int r = SDF_OpenDevice(&globalDevHandle);
        if (r)
        {
            printf("SDF_OpenDevice failed.\n");
            return -1;
        }

        //         // 初始化 sessionLink
        // #ifdef __APPLE__
        //         if (initSessionLink(sessionLink, -1))
        // #else
        //         if (initSessionLink(sessionLink, pthread_self()))
        // #endif
        //         {
        //             return -1;
        //         }

        // 初始化 keyLink
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
            if (!temp->expired)
            {
                r = SDF_DestroyKey(temp->sessionHandle, temp->keyHandle);
                if (r)
                {
                    printf("SDF_DestroyKey failed, ret: %x\n", r);
                }
                r = SDF_CloseSession(temp->sessionHandle);
                if (r)
                {
                    printf("SDF_CloseSession failed, ret: %x\n", r);
                }
            }

            // if (temp->session->sessionHandle)
            // {
            //     r = SDF_DestroyKey(temp->session->sessionHandle, temp->keyHandle);
            //     if (r)
            //     {
            //         printf("SDF_DestroyKey failed, ret: %x\n", r);
            //     }
            // }
            temp = temp->next;
        }

        r = SDF_CloseDevice(globalDevHandle);
        if (r)
        {
            printf("SDF_CloseDevice failed, ret: %x\n", r);
        }

        // // 关闭session
        // SESSION_LINK *tempSessionLink = sessionLink;
        // while (tempSessionLink)
        // {
        //     r = SDF_CloseSession(tempSessionLink->sessionHandle);
        //     if (r)
        //     {
        //         printf("SDF_CloseSession failed, ret: %x\n", r);
        //     }
        //     r = SDF_CloseDevice(tempSessionLink->devHandle);
        //     if (r)
        //     {
        //         printf("SDF_CloseDevice failed, ret: %x\n", r);
        //     }
        //     tempSessionLink = tempSessionLink->next;
        // }
        printf("ENGINE -> sdfSessionDestory finish\n");
    }

    static int initSessionLink(SESSION_LINK *link, long threadId)
    {
        printf("initSessionLink -> threadId: %ld\n", threadId);
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
#ifdef __APPLE__
        int threadId = pthread_mach_thread_np(pthread_self());
#else
        int threadId = pthread_self();
#endif
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
            printf("initKeyLink -> create new sdf session, threadid: %ld\n", threadId);
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

    static int initKeyLink(KEY_LINK *link, unsigned char *key, long threadId)
    {
        printf("initKeyLink -> threadId: %ld\n", threadId);

        int r;

        link->next = NULL;
        link->keyHandle = NULL;

        if (key)
        {
            if (keyNum >= MAX_SDF_KEY_NUM)
            {
                clearEarlyKey();
            }

            pthread_mutex_lock(&gMutex); // 加锁
            // 打开会话
            r = SDF_OpenSession(globalDevHandle, &link->sessionHandle);
            if (r)
            {
                pthread_mutex_unlock(&gMutex); // 解锁
                printf("SDF_OpenSession failed.\n");
                return r;
            }

            // SESSION_LINK *temp = NULL;
            // if (getSessionLink(&temp) != 0)
            // {
            //     return -1;
            // }
            // link->session = temp;

            r = SDF_ImportKey(link->sessionHandle, key, 16, &link->keyHandle);
            if (r)
            {
                pthread_mutex_unlock(&gMutex); // 解锁
                printf("SDF_ImportKey fail, ret: %x\n", r);
                return r;
            }
            keyNum += 1;

            pthread_mutex_unlock(&gMutex); // 解锁
            printf("SDF_ImportKey: %p\n", link->keyHandle);
            memcpy(link->key, key, 16);
        }
        return 0;
    }

    /**
     * TODO 清除最早使用的key
     */
    void clearEarlyKey()
    {
        int r = 0;
        KEY_LINK *expireKey = NULL;
        long nowTime = getTimeSecond();
        long maxEarlyTime = nowTime;

        KEY_LINK *preKey = NULL;
        KEY_LINK *temp = keyLink->next;
        while (temp)
        {
            // if (temp->expired)
            // {
            // }
            if (temp->useTime < maxEarlyTime)
            {
                maxEarlyTime = temp->useTime;
                expireKey = temp;
            }
            // if (temp->useTime - nowTime > MAX_SDF_KEY_SURVIVAL_TIME_SECOND)
            // {

            // }
            preKey = temp;
            temp = temp->next;
        }
        expireKey->expired = 1;

        pthread_mutex_lock(&gMutex); // 加锁
        preKey->next = temp->next;
        pthread_mutex_unlock(&gMutex); // 解锁

        // 销毁session key
        r = SDF_DestroyKey(expireKey->sessionHandle, expireKey->keyHandle);
        if (r)
        {
            printf("SDF_DestroyKey failed, ret: %x\n", r);
        }
        r = SDF_CloseSession(expireKey->sessionHandle);
        if (r)
        {
            printf("SDF_CloseSession failed, ret: %x\n", r);
        }
        free(preKey);
    }

    long getTimeSecond()
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);

        // printf("second: %ld\n", tv.tv_sec);                                 // 秒
        // printf("millisecond: %ld\n", tv.tv_sec * 1000 + tv.tv_usec / 1000); // 毫秒

        return tv.tv_sec;
    }

    int getKeyLink(KEY_LINK **link, unsigned char *key)
    {
        int r;
#ifdef __APPLE__
        int threadid = pthread_mach_thread_np(pthread_self());
#else
        long threadid = pthread_self();
#endif
        // printf("getKeyLink -> threadid: %ld\n", threadid);

        KEY_LINK *temp = keyLink->next;
        while (temp)
        {
            if (memcmp(temp->key, key, 16) == 0)
            {
                break;
            }
            temp = temp->next;
        }
        // if (temp && temp->expired)
        // {
        //     temp = NULL;
        // }
        if (!temp)
        {
            // printf("getKeyLink -> not find keyLink, threadid: %ld\n", threadid);
            temp = (KEY_LINK *)calloc(1, sizeof(KEY_LINK));
            if (!temp)
            {
                return -1;
            }
            if (initKeyLink(temp, key, threadid))
            {
                free(temp);
                return -1;
            }
            pthread_mutex_lock(&gMutex); // 加锁
            temp->next = keyLink->next;
            keyLink->next = temp;
            pthread_mutex_unlock(&gMutex); // 解锁
        }
        temp->useTime = getTimeSecond();
        *link = temp;
        return 0;
    }
#endif

#ifdef __cplusplus
}
#endif