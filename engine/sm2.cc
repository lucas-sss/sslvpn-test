/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-02-14 22:30:41
 * @LastEditors: liuwei lyy9645@163.com
 * @LastEditTime: 2024-03-13 22:54:39
 * @FilePath: \sslvpn-test\engine\sm2.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "sm2.h"
#include "sdf_type.h"
#include "ec_helper.h"
#include "sdf.h"
#include "key.h"

#ifdef __cplusplus
extern "C"
{
#endif
    static int ec_pkey_init(EVP_PKEY_CTX *ctx)
    {
        printf("ENGINE -> ec_pkey_init\n");
        pkey_init_func default_init;
        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
        EVP_PKEY_meth_get_init(pmeth, &default_init);

        return (*default_init)(ctx);
    }

    static int ec_pkey_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
    {
        printf("ENGINE -> ec_pkey_copy\n");
        pkey_copy_func default_copy;
        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
        EVP_PKEY_meth_get_copy(pmeth, &default_copy);

        return (*default_copy)(dst, src);
    }

    static void ec_pkey_cleanup(EVP_PKEY_CTX *ctx)
    {
        printf("ENGINE -> ec_pkey_cleanup\n");
        pkey_cleanup_func default_cleanup;
        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
        EVP_PKEY_meth_get_cleanup(pmeth, &default_cleanup);

        (*default_cleanup)(ctx);
    }

    static int ec_pkey_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
    {
        printf("ENGINE -> ec_pkey_paramgen\n");
        pkey_paramgen_init_func default_paramgen_init;
        pkey_paramgen_func default_paramgen;

        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
        EVP_PKEY_meth_get_paramgen(pmeth, &default_paramgen_init, &default_paramgen);

        return (*default_paramgen)(ctx, pkey);
    }

    static int ec_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
    {
        printf("ENGINE -> ec_pkey_keygen\n");
        pkey_keygen_init_func default_keygen_init;
        pkey_keygen_func default_keygen;

        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
        EVP_PKEY_meth_get_keygen(pmeth, &default_keygen_init, &default_keygen);

        return (*default_keygen)(ctx, pkey);
    }

    static int sdf_ec_pkey_sign_init(EVP_PKEY_CTX *ctx)
    {
        printf("ENGINE -> sdf_ec_pkey_sign_init\n");

        return 1;
    }

    static int sdf_ec_pkey_sign(EVP_PKEY_CTX *ctx, uint8_t *sig, size_t *siglen, const uint8_t *tbs, size_t tbslen)
    {
        printf("ENGINE -> sdf_ec_pkey_sign\n");
#ifndef NO_SDF
        int r;
        ECCSignature signature;
        ECCrefPrivateKey privateKey;
        unsigned char *pp = sig;

        memset(&privateKey, 0, sizeof(ECCrefPrivateKey));
        memset(&signature, 0, sizeof(ECCSignature));

        // 提取私钥
        EC_KEY *ec_key = (EC_KEY *)EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
        if (!EC_KEY_check_key(ec_key))
        {
            printf("ENGINE -> sdf_ec_pkey_sign: EC_KEY_check_key failed\n");
            return 0;
        }
        if (!EC_KEY_get_ECCrefPrivateKey(ec_key, &privateKey))
        {
            printf("ENGINE -> sdf_ec_pkey_sign: EC_KEY_get_ECCrefPrivateKey failed\n");
            return 0;
        }

        // 签名
        SESSION_LINK *link;
        r = getSessionLink(&link);
        if (r)
        {
            printf("ENGINE -> sdf_ec_pkey_sign: get sdf session fail, ret[%x]\n", r);
            return 0;
        }
        r = SDF_ExternalSign_ECC(link->sessionHandle, SGD_SM2_1, &privateKey, (unsigned char *)tbs, tbslen, &signature);
        // r = flk_SDF_IntSign_ECC(GUOXIN_SDF_KEY_INDEX, tbs, tbslen, &signature);
        if (r)
        {
            printf("ENGINE -> sdf_ec_pkey_sign: flk_SDF_ExtSign_ECC, ret[%x]\n", r);
            return 0;
        }

        // 编码sign
        r = i2d_ECCSignature(&signature, &pp);
        if (!r)
        {
            printf("ENGINE -> sdf_ec_pkey_sign: i2d_ECCSignature failed\n");
            return 0;
        }
        *siglen = r;
        return 1;
#else
    pkey_sign_func default_sign;
    pkey_sign_func_init default_sign_init;

    const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
    EVP_PKEY_meth_get_sign(pmeth, &default_sign_init, &default_sign);
    return (*default_sign)(ctx, sig, siglen, tbs, tbslen);
#endif
    }

    static int ec_pkey_verify(EVP_PKEY_CTX *ctx, const uint8_t *sig, size_t siglen, const uint8_t *tbs, size_t tbslen)
    {
        printf("ENGINE -> ec_pkey_verify\n");

#ifndef NO_SDF
        int r, derlen = -1;
        ECDSA_SIG *s;
        EC_KEY *ec_key = NULL;
        const unsigned char *pp = sig;
        unsigned char *der = NULL;

        ECCSignature signature;
        ECCrefPublicKey publicKey;

        memset(&signature, 0, sizeof(ECCSignature));
        memset(&publicKey, 0, sizeof(ECCrefPublicKey));

        // 检测sig格式是否正确
        if (!(s = ECDSA_SIG_new()))
        {
            printf("ENGINE -> ec_pkey_verify: ECDSA_SIG_new failed\n");
            return 0;
        }
        if (!d2i_ECDSA_SIG(&s, &pp, siglen))
        {
            printf("ENGINE -> ec_pkey_verify: d2i_ECDSA_SIG failed\n");
            return 0;
        }
        derlen = i2d_ECDSA_SIG(s, &der);
        if (derlen != siglen || memcmp(sig, der, derlen) != 0)
        {
            printf("ENGINE -> ec_pkey_verify: check sig format filed\n");
            return 0;
        }

        // 提取公钥
        ec_key = (EC_KEY *)EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));
        if (!EC_KEY_check_key(ec_key))
        {
            printf("ENGINE -> ec_pkey_verify: EC_KEY_check_key failed\n");
            return 0;
        }
        if (!EC_KEY_get_ECCrefPublicKey(ec_key, &publicKey))
        {
            printf("ENGINE -> ec_pkey_verify: EC_KEY_get_ECCrefPublicKey failed\n");
            return 0;
        }

        // sig转换
        if (!ECDSA_SIG_get_ECCSignature(s, &signature))
        {
            printf("ENGINE -> ec_pkey_verify: ECDSA_SIG_get_ECCSignature filed\n");
            return 0;
        }

        // 获取密码卡session
        SESSION_LINK *link;
        r = getSessionLink(&link);
        if (r)
        {
            printf("ENGINE -> ec_pkey_verify: get sdf session fail, ret[%x]\n", r);
            return 0;
        }
        // 验证签名
        r = SDF_ExternalVerify_ECC(link->sessionHandle, SGD_SM2_1, &publicKey, (unsigned char *)tbs, tbslen, &signature);
        //    r = flk_SDF_IntVerify_ECC(GUOXIN_SDF_KEY_INDEX, tbs, tbslen, &signature);
        if (r)
        {
            printf("ENGINE -> ec_pkey_verify: flk_SDF_ExtVerify_ECC filed, ret[%x]\n", r);
            return 0;
        }
        return 1;
#else
    pkey_verify_func default_verify;
    pkey_verify_init_func default_verify_init;

    const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
    EVP_PKEY_meth_get_verify(pmeth, &default_verify_init, &default_verify);
    return (*default_verify)(ctx, sig, siglen, tbs, tbslen);
#endif
    }

    static int ec_pkey_encrypt(EVP_PKEY_CTX *ctx, uint8_t *out,
                               size_t *outlen, const uint8_t *in, size_t inlen)
    {
        printf("ENGINE -> ec_pkey_encrypt\n");
        return 0;
    }

    static int ec_pkey_decrypt(EVP_PKEY_CTX *ctx, uint8_t *out,
                               size_t *outlen, const uint8_t *in, size_t inlen)
    {
        printf("ENGINE -> ec_pkey_decrypt\n");
        return 0;
    }

    static int ec_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
    {
        pkey_ctrl_func default_ctrl;
        pkey_ctrl_str_func default_ctrl_str;

        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
        EVP_PKEY_meth_get_ctrl(pmeth, &default_ctrl, &default_ctrl_str);

        return (*default_ctrl)(ctx, type, p1, p2);
    }

    static int ec_pkey_derive(EVP_PKEY_CTX *ctx, uint8_t *key, size_t *keylen)
    {
        pkey_derive_func default_derive;
        pkey_derive_init_func default_derive_init;

        const EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
        EVP_PKEY_meth_get_derive(pmeth, &default_derive_init, &default_derive);

        return (*default_derive)(ctx, key, keylen);
    }

    typedef struct _pkey_info
    {
        EVP_PKEY_METHOD *pMethod;
    } pkey_info_t;

#define PKEY_NID_NUM 1
    // static EVP_PKEY_METHOD *pMethod = NULL;
    static pkey_info_t info[PKEY_NID_NUM];
    static EVP_PKEY_METHOD *pkey_ec_method(void)
    {
        if ((info[0].pMethod = EVP_PKEY_meth_new(EVP_PKEY_EC, 0)) == NULL)
        {
            printf("ENGINE -> pkey_ec_method: EVP_PKEY_meth_new fail\n");
            return NULL;
        }

        EVP_PKEY_meth_set_init(info[0].pMethod, ec_pkey_init);
        EVP_PKEY_meth_set_copy(info[0].pMethod, ec_pkey_copy);
        EVP_PKEY_meth_set_cleanup(info[0].pMethod, ec_pkey_cleanup);
        EVP_PKEY_meth_set_paramgen(info[0].pMethod, NULL, ec_pkey_paramgen);
        EVP_PKEY_meth_set_keygen(info[0].pMethod, NULL, ec_pkey_keygen);
        EVP_PKEY_meth_set_sign(info[0].pMethod, sdf_ec_pkey_sign_init, sdf_ec_pkey_sign);
        EVP_PKEY_meth_set_verify(info[0].pMethod, NULL, ec_pkey_verify);
        EVP_PKEY_meth_set_encrypt(info[0].pMethod, NULL, ec_pkey_encrypt);
        EVP_PKEY_meth_set_decrypt(info[0].pMethod, NULL, ec_pkey_decrypt);
        EVP_PKEY_meth_set_derive(info[0].pMethod, NULL, ec_pkey_derive);
        EVP_PKEY_meth_set_ctrl(info[0].pMethod, ec_pkey_ctrl, NULL);

        return info[0].pMethod;
    }

    static int pkey_nids[] = {
        EVP_PKEY_EC};

    int ssl_engine_ec_pkey(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
    {
        printf("ENGINE -> ssl_engine_ec_pkey: nid[%d]\n", nid);

        if (pmeth == NULL)
        {
            *nids = pkey_nids;
            return (sizeof(pkey_nids) / sizeof(pkey_nids[0]));
        }
        *pmeth = NULL;

        switch (nid)
        {
        case EVP_PKEY_EC:
            *pmeth = pkey_ec_method();
            // *pmeth = ec_pkey_method();
            break;
        default:
            printf("ENGINE -> Not support nid[%d] for ec pkey\n", nid);
            break;
        }
        return (*pmeth != NULL);
    }

#ifdef __cplusplus
}
#endif