#ifndef __ENGINE_EC_HELPER_H__
#define __ENGINE_EC_HELPER_H__

#include <openssl/ec.h>
#include "sdf_type.h"

#ifdef __cplusplus
extern "C"
{
#endif
    int EC_KEY_get_ECCrefPrivateKey(EC_KEY *ec_key, ECCrefPrivateKey *ref);

    int EC_KEY_get_ECCrefPublicKey(EC_KEY *ec_key, ECCrefPublicKey *ref);

    int i2d_ECCSignature(ECCSignature *a, unsigned char **pp);

    int ECDSA_SIG_set_ECCSignature(ECDSA_SIG *sig, const ECCSignature *ref);
    int ECDSA_SIG_get_ECCSignature(const ECDSA_SIG *sig, ECCSignature *ref);
#ifdef __cplusplus
}
#endif

#endif