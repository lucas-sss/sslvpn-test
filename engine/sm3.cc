/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-04-05 20:41:49
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-04-08 10:46:19
 * @FilePath: \sslvpn-test\engine\sm3.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <stdio.h>
#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include "sm3.h"
#include "sdf_handler.h"
#include "sdf.h"

typedef struct
{
    int nid;
    EVP_MD *digest;
} digest_info_t;

typedef struct
{
    unsigned long num;
    unsigned char buf[2048 << 1];
} EVP_SM3_SDF_CTX;

static int digestNids[] = {
    NID_sm3, // 不同的ssl库nid的值时不一样的，各个厂家的国密实现不一样
    // NID_hmacWithSM3,
};

static digest_info_t digestInfos[] = {
    {NID_sm3, NULL},
    // {NID_hmacWithSM3, NULL},
};

#ifdef __cplusplus
extern "C"
{
#endif

    static int
    sdf_digest_init(EVP_MD_CTX *ctx)
    {
        // printf("ENGINE -> sdf_digest_init\n");
#ifndef NO_SDF
        if (!ctx || !EVP_MD_CTX_md_data(ctx))
        {
            return 0;
        }
        EVP_SM3_SDF_CTX *sm3SdfCtx = (EVP_SM3_SDF_CTX *)EVP_MD_CTX_md_data(ctx);
        memset(sm3SdfCtx, 0, sizeof(EVP_SM3_SDF_CTX));
        sm3SdfCtx->num = 0;
        return 1;
#else
    return EVP_MD_meth_get_init(EVP_sm3())(ctx);
#endif
    }

    static int sdf_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
    {
        // printf("ENGINE -> sdf_digest_update, count: %d\n", count);
#ifndef NO_SDF
        if (!ctx || !EVP_MD_CTX_md_data(ctx) || (!data && count != 0))
        {
            return 0;
        }
        EVP_SM3_SDF_CTX *sm3SdfCtx = (EVP_SM3_SDF_CTX *)EVP_MD_CTX_md_data(ctx);
        if ((sm3SdfCtx->num + count) > sizeof(sm3SdfCtx->buf))
        {
            printf("ENGINE -> sdf_digest_update fail, all data length[%d] is too long", sm3SdfCtx->num + count);
            return 0;
        }
        memcpy(sm3SdfCtx->buf + sm3SdfCtx->num, data, count);
        sm3SdfCtx->num += count;
        return 1;
#else
    return EVP_MD_meth_get_update(EVP_sm3())(ctx, data, count);
#endif
    }

    static int sdf_digest_final(EVP_MD_CTX *ctx, unsigned char *md)
    {
        // printf("ENGINE -> sdf_digest_final\n");
#ifndef NO_SDF
        int r;
        unsigned int md_len = 0;

        if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md)
        {
            return 0;
        }

        EVP_SM3_SDF_CTX *sm3SdfCtx = (EVP_SM3_SDF_CTX *)EVP_MD_CTX_md_data(ctx);

        SESSION_LINK *sessionLink = NULL;
        r = getSessionLink(&sessionLink);
        if (r)
        {
            printf("ENGINE -> sdf_digest_final: getSessionLink fail, ret: %x\n", r);
            return 0;
        }
        r = SDF_HashInit(sessionLink->sessionHandle, SGD_SM3, NULL, NULL, 0);
        if (r)
        {
            printf("ENGINE -> sdf_digest_final: SDF_HashInit, ret: %x\n", r);
            return 0;
        }
        r = SDF_HashUpdate(sessionLink->sessionHandle, sm3SdfCtx->buf, sm3SdfCtx->num);
        if (r)
        {
            printf("ENGINE -> sdf_digest_final: SDF_HashUpdate, ret: %x\n", r);
            return 0;
        }
        r = SDF_HashFinal(sessionLink->sessionHandle, md, &md_len);
        if (r)
        {
            printf("ENGINE -> sdf_digest_final: SDF_HashFinal, ret: %x\n", r);
            return 0;
        }
#else
    return EVP_MD_meth_get_final(EVP_sm3())(ctx, md);
#endif
        return 1;
    }

    static EVP_MD *_hidden_sm3_sdf = NULL;
    static const EVP_MD *EVP_sm3_sdf()
    {
        if (_hidden_sm3_sdf == NULL && ((_hidden_sm3_sdf = EVP_MD_meth_new(NID_sm3, NID_SM2_with_SM3)) == NULL ||
                                        !EVP_MD_meth_set_flags(_hidden_sm3_sdf, 16) ||
                                        !EVP_MD_meth_set_input_blocksize(_hidden_sm3_sdf, 64) ||
                                        !EVP_MD_meth_set_result_size(_hidden_sm3_sdf, 32) ||
#ifndef NO_SDF
                                        !EVP_MD_meth_set_init(_hidden_sm3_sdf, sdf_digest_init) ||
                                        !EVP_MD_meth_set_update(_hidden_sm3_sdf, sdf_digest_update) ||
                                        !EVP_MD_meth_set_final(_hidden_sm3_sdf, sdf_digest_final) ||
                                        !EVP_MD_meth_set_app_datasize(_hidden_sm3_sdf, sizeof(EVP_SM3_SDF_CTX))))
#else
                                        !EVP_MD_meth_set_init(_hidden_sm3_sdf, EVP_MD_meth_get_init(EVP_sm3())) ||
                                        !EVP_MD_meth_set_update(_hidden_sm3_sdf, EVP_MD_meth_get_update(EVP_sm3())) ||
                                        !EVP_MD_meth_set_final(_hidden_sm3_sdf, EVP_MD_meth_get_final(EVP_sm3())) ||
                                        !EVP_MD_meth_set_app_datasize(_hidden_sm3_sdf, EVP_MD_meth_get_app_datasize(EVP_sm3()))) // 软算法
#endif

        {
            printf("EVP_sm4_cbc_sdf() -> error\n");
            EVP_MD_meth_free(_hidden_sm3_sdf);
            _hidden_sm3_sdf = NULL;
        }
        return _hidden_sm3_sdf;
    }

    static const EVP_MD *ssl_engine_digest_sw_impl(int nid)
    {
        printf("ENGINE -> ssl_engine_digest_sw_impl: nid[%d]\n", nid);

        switch (nid)
        {
        case NID_sm3:
            return EVP_sm3_sdf();
        // case NID_hmacWithSM3:
        //     return EVP_sm3();
        //     return NULL;
        default:
            fprintf(stdout, "ENGINE -> Not support nid[%d] for digest\n", nid);
            return NULL;
        }
    }

    static const EVP_MD *ssl_engine_get_digest(int nid)
    {
        int i;
        for (i = 0; i < sizeof(digestInfos) / sizeof(digest_info_t); i++)
            if (digestInfos[i].nid == nid)
                return digestInfos[i].digest;

        return NULL;
    }

    int ssl_engine_create_digest(void)
    {
        printf("ENGINE -> ssl_engine_create_digest\n");

        int i;
        for (i = 0; i < sizeof(digestInfos) / sizeof(digest_info_t); i++)
        {
            const EVP_MD *temp = ssl_engine_digest_sw_impl(digestInfos[i].nid);
            digestInfos[i].digest = EVP_MD_meth_dup(temp);
        }
        return 1;
    }

    int ssl_engine_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
    {
        printf("ENGINE -> ssl_engine_digests: nid[%d]\n", nid);
        if (!digest)
        {
            *nids = digestNids;
            return (sizeof(digestNids) / sizeof(digestNids[0]));
        }
        *digest = ssl_engine_get_digest(nid);
        return (*digest != NULL);
    }

#ifdef __cplusplus
}
#endif