/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-02-05 14:34:28
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-04-09 00:14:26
 * @FilePath: \sslvpn-test\engine\sslengine.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */

#include <stdio.h>
#include "random.h"
#include "sm4.h"
#include "sm3.h"
#include "sm2.h"
#include "ssl_engine.h"
#include "sdf_handler.h"

#ifdef __cplusplus
extern "C"
{
#endif

    const char *engine_id = "flk_ssl_engine";
    const char *engine_name = "flk ssl engine for tongsuo";

    static int engine_init(ENGINE *e)
    {
        printf("ENGINE -> engine_init\n");
#ifndef NO_SDF
        if (sdfSessionInit() != 0)
        {
            printf("sdf session init fail\n");
        }
#endif
        return 1;
    }

    static int engine_finish(ENGINE *e)
    {
        printf("ENGINE -> engine_finish\n");
#ifndef NO_SDF
        sdfSessionDestory();
#endif
        return 1;
    }

    static int engine_destroy(ENGINE *e)
    {
        printf("ENGINE -> engine_destroy\n");
        return 1;
    }

    static int _bind_engine(ENGINE *e)
    {
        printf("ENGINE -> bind_flk_ssl_engine\n");

        int ret = 1;

        ssl_engine_create_cipher();
        ssl_engine_create_digest();

        ret &= ENGINE_set_id(e, engine_id);
        ret &= ENGINE_set_name(e, engine_name);

        // 设置随机数
        ret &= ENGINE_set_RAND(e, ssl_engine_rand());

        // 设置sm4
        ret &= ENGINE_set_ciphers(e, ssl_engine_ciphers);
        // 设置sm3
        ret &= ENGINE_set_digests(e, ssl_engine_digests);
        // 设置sm2
        // ret &= ENGINE_set_pkey_meths(e, ssl_engine_ec_pkey);

        ret &= ENGINE_set_destroy_function(e, engine_destroy);
        ret &= ENGINE_set_init_function(e, engine_init);
        ret &= ENGINE_set_finish_function(e, engine_finish);

        _assert(ret != 0, ret);

        return ret;
    }

    ENGINE *register_engine()
    {
        ENGINE *e = ENGINE_new();
        if (!e)
        {
            return NULL;
        }
        if (!_bind_engine(e))
        {
            return NULL;
        }
        ENGINE_add(e);
        ENGINE_free(e);

        ENGINE *engine = NULL;
        engine = ENGINE_by_id("flk_ssl_engine"); // 通过id返回engine对象
        if (engine != NULL)
        {
            printf("load engine name: %s\n", ENGINE_get_name(engine));
            ENGINE_register_all_RAND();
            ENGINE_register_all_ciphers();
            ENGINE_register_all_digests();
            ENGINE_register_all_pkey_meths();
            ENGINE_set_default(engine, ENGINE_METHOD_ALL);
            return engine;
        }
        printf("load engine fail\n");
        return NULL;
    }

    static int bind_helper(ENGINE *e, const char *id)
    {
        if (id && (strcmp(id, engine_id) != 0))
            return 0;
        if (!_bind_engine(e))
            return 0;
        return 1;
    }

    IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)

#ifdef __cplusplus
}
#endif