/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-02-16 20:30:51
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-02-16 21:29:52
 * @FilePath: \sslvpn-test\engine\ec_helper.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <openssl/ec.h>
#include "ec_helper.h"

#ifdef __cplusplus
extern "C"
{
#endif
    static ECDSA_SIG *ECDSA_SIG_new_from_ECCSignature(const ECCSignature *ref);

    int EC_KEY_get_ECCrefPrivateKey(EC_KEY *ec_key, ECCrefPrivateKey *ref)
    {
        const EC_GROUP *group;
        const BIGNUM *sk;

        /* check arguments */
        if (!ec_key || !ref)
        {
            return 0;
        }

        group = EC_KEY_get0_group(ec_key);
        sk = EC_KEY_get0_private_key(ec_key);

        if (!group || !sk)
        {
            return 0;
        }

        if (EC_GROUP_get_degree(group) > 512)
        {
            return 0;
        }

        /* EC_KEY ==> ECCrefPrivateKey */
        memset(ref, 0, sizeof(*ref));

        ref->bits = EC_GROUP_get_degree(group);

        if (!BN_bn2bin(sk, ref->K + sizeof(ref->K) - BN_num_bytes(sk)))
        {
            return 0;
        }

        return 1;
    }

    int EC_KEY_get_ECCrefPublicKey(EC_KEY *ec_key, ECCrefPublicKey *ref)
    {
        int ret = 0;
        BN_CTX *bn_ctx = NULL;
        const EC_GROUP *group = EC_KEY_get0_group(ec_key);
        const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
        BIGNUM *x;
        BIGNUM *y;

        /* check arguments */
        if (!ec_key || !ref)
        {
            return 0;
        }

        /* prepare */
        if (!(bn_ctx = BN_CTX_new()))
        {
            goto end;
        }
        BN_CTX_start(bn_ctx);
        x = BN_CTX_get(bn_ctx);
        y = BN_CTX_get(bn_ctx);
        if (!x || !y)
        {
            goto end;
        }

        if (EC_GROUP_get_degree(group) > ECCref_MAX_BITS)
        {
            goto end;
        }

        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == 406)
        {
            if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bn_ctx))
            {
                goto end;
            }
        }
        else
        {
            if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, bn_ctx))
            {
                goto end;
            }
        }

        /* EC_KEY ==> ECCrefPublicKey */
        memset(ref, 0, sizeof(*ref));
        ref->bits = EC_GROUP_get_degree(group);
        if (!BN_bn2bin(x, ref->x + ECCref_MAX_LEN - BN_num_bytes(x)))
        {
            goto end;
        }
        if (!BN_bn2bin(y, ref->y + ECCref_MAX_LEN - BN_num_bytes(y)))
        {
            goto end;
        }

        ret = 1;
    end:
        if (bn_ctx)
        {
            BN_CTX_end(bn_ctx);
        }
        BN_CTX_free(bn_ctx);
        return ret;
    }

    int i2d_ECCSignature(ECCSignature *a, unsigned char **pp)
    {
        int ret;
        ECDSA_SIG *sig = NULL;

        if (!(sig = ECDSA_SIG_new_from_ECCSignature(a)))
        {
            return 0;
        }

        ret = i2d_ECDSA_SIG(sig, pp);
        ECDSA_SIG_free(sig);
        return ret;
    }

    static ECDSA_SIG *ECDSA_SIG_new_from_ECCSignature(const ECCSignature *ref)
    {
        ECDSA_SIG *ret = NULL;
        ECDSA_SIG *sig = NULL;

        /* check arguments */
        if (!ref)
        {
            return NULL;
        }

        /* generate and convert */
        if (!(sig = ECDSA_SIG_new()))
        {
        }
        if (!ECDSA_SIG_set_ECCSignature(sig, ref))
        {
            goto end;
        }

        /* set return value */
        ret = sig;
        sig = NULL;

    end:
        ECDSA_SIG_free(sig);
        return ret;
    }

    int ECDSA_SIG_set_ECCSignature(ECDSA_SIG *sig, const ECCSignature *ref)
    {
        int ret = 0;
        BIGNUM *r = NULL;
        BIGNUM *s = NULL;

        /* check arguments */
        if (!sig || !ref)
        {
            return 0;
        }

        /* ECCSignature ==> ECDSA_SIG */
        if (!(r = BN_bin2bn(ref->r, ECCref_MAX_LEN, NULL)))
        {
            goto end;
        }
        if (!(s = BN_bin2bn(ref->s, ECCref_MAX_LEN, NULL)))
        {
            goto end;
        }
        /* when using `sm2p256v1`, we need to check (s, r) length correct */
        if (BN_num_bytes(r) != 256 / 8 || BN_num_bytes(s) != 256 / 8)
        {
            goto end;
        }

        /* set return value
         * `ECDSA_SIG_set0` should make sure that if failed, do not accept
         * the value of (r, s), or there will be double-free
         */
        if (!ECDSA_SIG_set0(sig, r, s))
        {
            goto end;
        }

        r = NULL;
        s = NULL;
        ret = 1;

    end:
        BN_free(r);
        BN_free(s);
        return ret;
    }

    int ECDSA_SIG_get_ECCSignature(const ECDSA_SIG *sig, ECCSignature *ref)
    {
        /* (r, s) are pointed to (sig->r, sig->s), so dont free (r, s) */
        const BIGNUM *r = NULL;
        const BIGNUM *s = NULL;

        /* check arguments */
        if (!sig || !ref)
        {
            return 0;
        }

        /* check ECDSA_SIG
         * `ECDSA_SIG_get0() return void
         */
        ECDSA_SIG_get0(sig, &r, &s);

        if (BN_num_bytes(r) > ECCref_MAX_LEN ||
            BN_num_bytes(s) > ECCref_MAX_LEN)
        {
            return 0;
        }

        /* ECDSA_SIG ==> ECCSignature */
        // memset(ref, 0, sizeof(*ref));

        if (!BN_bn2bin(r, ref->r + ECCref_MAX_LEN - BN_num_bytes(r)))
        {
            return 0;
        }
        if (!BN_bn2bin(s, ref->s + ECCref_MAX_LEN - BN_num_bytes(s)))
        {
            return 0;
        }

        return 1;
    }

#ifdef __cplusplus
}
#endif
