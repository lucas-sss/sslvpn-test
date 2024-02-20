
#ifndef __SSLENGINE_H__
#define __SSLENGINE_H__

#include <openssl/engine.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define _assert(cond, ret)                                                            \
    do                                                                                \
    {                                                                                 \
        if (!(cond))                                                                  \
        {                                                                             \
            printf("assert: '" #cond "' failed [%s line: %d]\n", __FILE__, __LINE__); \
            return ret;                                                               \
        }                                                                             \
    } while (0)

    ENGINE *register_engine();

#ifdef __cplusplus
}
#endif

#endif /* __SSLENGINE_H__ */
