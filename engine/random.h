/**
 *
 * Created by liuwei@flksec.com on 09/01/2020.
 */
#ifndef FLK_SSL_ENGINE_RANDOM_H
#define FLK_SSL_ENGINE_RANDOM_H

#include <openssl/rand.h>
#include <openssl/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    const RAND_METHOD *ssl_engine_rand();

#ifdef __cplusplus
}
#endif
#endif // FLK_SSL_ENGINE_RANDOM_H
