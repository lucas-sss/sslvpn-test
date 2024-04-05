#ifndef __ENGINE_SM3_H__
#define __ENGINE_SM3_H__

#include <openssl/types.h>

#ifdef __cplusplus
extern "C"
{
#endif
    int ssl_engine_create_digest(void);

    int ssl_engine_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);

#ifdef __cplusplus
}
#endif

#endif