/**
 *
 * Created by liuwei@flksec.com on 09/01/2020.
 */
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <stdio.h>

#include "cipher.h"

#ifdef __cplusplus
extern "C"
{
#endif

    static int sdf_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
    {
#ifdef SDF
        EVP_SM4_CBC_SDF_CTX *key_ctx = (EVP_SM4_CBC_SDF_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
        memcpy(key_ctx->key, key, SM4_KEY_LENGTH);
        key_ctx->enc = enc;
        return 1;
#else
    return EVP_CIPHER_meth_get_init(EVP_sm4_cbc())(ctx, key, iv, enc);
#endif
    }

    static int sdf_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
    {
#ifdef SDF
        int r, l;
        unsigned char key[16] = {0};
        unsigned char iv[16] = {0};
        EVP_SM4_CBC_SDF_CTX *key_ctx;

        if (!out || !in)
        {
            return 0;
        }

        key_ctx = (EVP_SM4_CBC_SDF_CTX *)EVP_CIPHER_CTX_get_cipher_data(ctx);
        memcpy(key, key_ctx->key, 16);
        memcpy(iv, EVP_CIPHER_CTX_iv_noconst(ctx), 16);

        // 直接拷贝，不加密
        memcpy(out, in, inl);

        return 1;
#else
    // unsigned char *tmpbuf;
    // int ret;

    // tmpbuf = (unsigned char *)OPENSSL_malloc(inl);

    // /* OPENSSL_malloc will return NULL if inl == 0 */
    // if (tmpbuf == NULL && inl > 0)
    //     return -1;

    // /* Remember what we were asked to encrypt */
    // if (tmpbuf != NULL)
    //     memcpy(tmpbuf, in, inl);

    // /* Throw it all away and just use the plaintext as the output */
    // if (tmpbuf != NULL)
    //     memcpy(out, tmpbuf, inl);
    // OPENSSL_free(tmpbuf);
    memcpy(out, in, inl);
    return 1;

    /* Go through the motions of encrypting it */
    // return EVP_CIPHER_meth_get_do_cipher(EVP_sm4_cbc())(ctx, out, in, inl);
#endif
    }

    static EVP_CIPHER *_hidden_sm4_cbc_sdf = NULL;

    static EVP_CIPHER *EVP_sm4_cbc_sdf()
    {
        if (_hidden_sm4_cbc_sdf == NULL && ((_hidden_sm4_cbc_sdf = EVP_CIPHER_meth_new(NID_sm4_cbc, 16, 16)) == NULL ||
                                            !EVP_CIPHER_meth_set_iv_length(_hidden_sm4_cbc_sdf, 16) ||
                                            !EVP_CIPHER_meth_set_flags(_hidden_sm4_cbc_sdf, EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE) ||
                                            !EVP_CIPHER_meth_set_init(_hidden_sm4_cbc_sdf, sdf_cipher_init) ||
                                            !EVP_CIPHER_meth_set_do_cipher(_hidden_sm4_cbc_sdf, sdf_do_cipher) ||
                                            !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_sm4_cbc_sdf, EVP_CIPHER_impl_ctx_size(EVP_sm4_cbc()))))
        {
            printf("EVP_sm4_cbc_sdf() -> error\n");
            EVP_CIPHER_meth_free(_hidden_sm4_cbc_sdf);
            _hidden_sm4_cbc_sdf = NULL;
        }
        return _hidden_sm4_cbc_sdf;
    }

    static int ciphers_nids[] = {
        NID_sm4_ecb,
        NID_sm4_cbc,
        NID_sm4_ctr};

    static cipher_info_t info[] = {
        // sm4
        {NID_sm4_ecb, NULL},
        {NID_sm4_cbc, NULL},
        {NID_sm4_ctr, NULL},
    };

    static const EVP_CIPHER *flk_ssl_engine_cipher_sw_impl(int nid)
    {
        //    printf("ENGINE -> flk_gmssl_engine_cipher_sw_impl: nid[%d]\n", nid);

        switch (nid)
        {
        case NID_sm4_ecb:
            return EVP_sm4_ecb();
        case NID_sm4_cbc:
#ifdef SDF
            return EVP_sm4_cbc_sdf();
#else
        return EVP_sm4_cbc_sdf();
        // return EVP_sm4_cbc();
#endif
        case NID_sm4_ctr:
            return EVP_sm4_ctr();
        default:
            printf("Invalid nid %d\n", nid);
            return NULL;
        }
    }

    static const EVP_CIPHER *flk_ssl_engine_get_cipher(int nid)
    {
        int i;
        for (i = 0; i < sizeof(info) / sizeof(cipher_info_t); i++)
            if (info[i].nid == nid)
                return info[i].cipher;

        return NULL;
    }

    int flk_ssl_engine_create_cipher(void)
    {
        int i;
        for (i = 0; i < sizeof(info) / sizeof(cipher_info_t); i++)
        {
            const EVP_CIPHER *temp = flk_ssl_engine_cipher_sw_impl(info[i].nid);
            info[i].cipher = EVP_CIPHER_meth_dup(temp);
        }
        return 1;
    }

    int flk_ssl_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
    {
        if (!cipher)
        {
            *nids = ciphers_nids;
            return (sizeof(ciphers_nids) / sizeof(ciphers_nids[0]));
        }
        *cipher = flk_ssl_engine_get_cipher(nid);
        return (*cipher != NULL);
    }

#ifdef __cplusplus
}
#endif