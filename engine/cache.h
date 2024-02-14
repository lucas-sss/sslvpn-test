/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2024-02-06 16:22:30
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2024-02-06 17:27:54
 * @FilePath: \sslvpn-test\engine\cache.h
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#ifndef CACHE_H
#define CACHE_H

#ifdef __cplusplus
extern "C"
{
#endif
    int sdfSessionInit();
    int sdfSessionDestory();

    int getSdfSession(void **handle);

#ifdef __cplusplus
}
#endif
#endif // CACHE_H