/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-09-21 01:25:52
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2023-09-21 01:27:11
 * @FilePath: \sslvpn-test\print.cc
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */

#include <stdio.h>

#include "print.h"

#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * dump_hex
     *
     * @brief dump data in hex format
     *
     * @param buf: User buffer
     * @param size: Dump data size
     * @param number: The number of outputs per line
     *
     * @return void
     */
    void dump_hex(const uint8_t *buf, uint32_t size, uint32_t number)
    {
        int i, j;

        for (i = 0; i < size; i += number)
        {
            printf("%08X: ", i);

            for (j = 0; j < number; j++)
            {
                if (j % 8 == 0)
                {
                    printf(" ");
                }
                if (i + j < size)
                    printf("%02X ", buf[i + j]);
                else
                    printf("   ");
            }
            printf(" ");

            for (j = 0; j < number; j++)
            {
                if (i + j < size)
                {
                    printf("%c", __is_print(buf[i + j]) ? buf[i + j] : '.');
                }
            }
            printf("\n");
        }
    }

#ifdef __cplusplus
}
#endif