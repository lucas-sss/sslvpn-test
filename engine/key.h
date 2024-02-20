/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-02-06 16:22:30
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-02-20 21:57:35
 * @FilePath: \sslvpn-test\engine\cache.h
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#ifndef CACHE_H
#define CACHE_H

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct sessionlink_t
    {
        void *devHandle;
        void *sessionHandle;
        int threadid;
        struct sessionlink_t *next;
    } SESSION_LINK;

    typedef struct keylink_t
    {
        SESSION_LINK *session;
        void *keyHandle;
        unsigned char key[16];
        struct keylink_t *next;
    } KEY_LINK;

    int sdfSessionInit();
    int sdfSessionDestory();

    extern KEY_LINK *keyLink;
    int getKeyLink(KEY_LINK **link, unsigned char *key);

#ifdef __cplusplus
}
#endif
#endif // CACHE_H