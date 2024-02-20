/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-12-06 18:11:27
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-02-16 16:45:56
 * @FilePath: \FLK_ssl_engine\src\cipher.h
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
/**
 *
 * Created by liuwei@flksec.com on 09/01/2020.
 */
#ifndef __ENGINE_SM4_H__
#define __ENGINE_SM4_H__

#include <openssl/engine.h>
#include <openssl/modes.h>

#define SM4_KEY_LENGTH 16

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct cipher_ctx_
    {
        int nid;
        EVP_CIPHER *cipher;
    } cipher_info_t;

    typedef struct
    {
        int enc;
        unsigned char key[SM4_KEY_LENGTH];
        unsigned char iv[SM4_KEY_LENGTH];
    } EVP_SM4_CBC_SDF_CTX;

    int ssl_engine_create_cipher(void);

    int ssl_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);

#ifdef __cplusplus
}
#endif

#endif
