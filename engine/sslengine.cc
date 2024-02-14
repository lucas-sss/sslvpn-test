
#include <stdio.h>
#include "cipher.h"
#include "sslengine.h"
#include "cache.h"

#ifdef __cplusplus
extern "C"
{
#endif

    const char *engine_id = "flk_ssl_engine";
    const char *engine_name = "flk ssl engine for tongsuo";

    static int engine_init(ENGINE *e)
    {
        printf("ENGINE -> engine_init\n");
        if (sdfSessionInit() != 0)
        {
            printf("sdf session init fail\n");
        }
        return 1;
    }

    static int engine_finish(ENGINE *e)
    {
        printf("ENGINE -> engine_finish\n");
        sdfSessionDestory();
        return 1;
    }

    static int engine_destroy(ENGINE *e)
    {
        printf("ENGINE -> engine_destroy\n");
        return 1;
    }

    static int bind_engine(ENGINE *e)
    {
        printf("ENGINE -> bind_flk_ssl_engine\n");

        int ret = 1;

        flk_ssl_engine_create_cipher();

        ret &= ENGINE_set_id(e, engine_id);
        ret &= ENGINE_set_name(e, engine_name);

        // 设置sm4
        ret &= ENGINE_set_ciphers(e, flk_ssl_engine_ciphers);

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
        if (!bind_engine(e))
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
            ENGINE_register_ciphers(engine);
            ENGINE_register_all_ciphers();
            // ENGINE_register_all_digests();
            ENGINE_set_default(engine, ENGINE_METHOD_ALL);
            return engine;
        }
        printf("load engine fail\n");
        return NULL;
    }

#ifdef __cplusplus
}
#endif