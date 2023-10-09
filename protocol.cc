/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-09-06 14:21:55
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2023-10-09 21:09:15
 * @FilePath: \SSL-TEST\protocol.c
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "protocol.h"

#ifdef __cplusplus
extern "C"
{
#endif
    const unsigned int HEADER_LEN = VPN_LABEL_LEN + RECORD_TYPE_LABEL_LEN + RECORD_LENGTH_LABEL_LEN;
    const unsigned int RECORD_HEADER_LEN = RECORD_TYPE_LABEL_LEN + RECORD_LENGTH_LABEL_LEN;

    const unsigned char VPN_LABEL[VPN_LABEL_LEN] = {0x10, 0x10}; // vpn数据标记
    const unsigned char RECORD_TYPE_DATA[RECORD_TYPE_LABEL_LEN] = {0x11, 0x10};
    const unsigned char RECORD_TYPE_CONTROL[RECORD_TYPE_LABEL_LEN] = {0x12, 0x10};
    const unsigned char RECORD_TYPE_CONTROL_TUN_CONFIG[RECORD_TYPE_LABEL_LEN] = {0x12, 0x11};
    const unsigned char RECORD_TYPE_CONTROL_ROUTE_CONFIG[RECORD_TYPE_LABEL_LEN] = {0x12, 0x12};
    const unsigned char RECORD_TYPE_AUTH[RECORD_TYPE_LABEL_LEN] = {0x13, 0x10};
    const unsigned char RECORD_TYPE_ALARM[RECORD_TYPE_LABEL_LEN] = {0x14, 0x10};

    int enpack(const unsigned char type[RECORD_TYPE_LABEL_LEN], unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len)
    {
        if (in == NULL || out == NULL || out_len == NULL)
        {
            return -1;
        }

        if (in_len + HEADER_LEN > *out_len)
        {
            return -1;
        }

        int len = 0;

        memcpy(out, VPN_LABEL, VPN_LABEL_LEN);
        len += VPN_LABEL_LEN;
        memcpy(out + len, type, RECORD_TYPE_LABEL_LEN);
        len += RECORD_TYPE_LABEL_LEN;
        memcpy(out + len, &in_len, RECORD_LENGTH_LABEL_LEN);
        len += RECORD_LENGTH_LABEL_LEN;
        memcpy(out + len, in, in_len);
        len += in_len;
        *out_len = len;

        return 0;
    }

    int depack(unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len, unsigned char **next, unsigned int *next_len)
    {
        if (in == NULL || out == NULL || next == NULL || next_len == NULL)
        {
            return 0;
        }

        if (in_len < HEADER_LEN)
        { // 数据不足消息头长度
            *next = in;
            *next_len = in_len;
            return 0;
        }

        if (memcmp(in, VPN_LABEL, VPN_LABEL_LEN) == 0)
        { // 是vpn协议才进行解析
            unsigned int *length = (unsigned int *)(in + VPN_LABEL_LEN + RECORD_TYPE_LABEL_LEN);
            if (in_len < (HEADER_LEN + *length))
            { // 剩余可解析数据长度小于标记长度，需要继续读取
                *next = in;
                *next_len = in_len;
                return 0;
            }

            if (*out_len < (RECORD_HEADER_LEN + *length))
            { // 输出缓存数据长度不够
                *next = in;
                *next_len = in_len;
                return 0;
            }

            memcpy(out, in + VPN_LABEL_LEN, RECORD_HEADER_LEN + *length);
            *out_len = (RECORD_HEADER_LEN + *length);

            if (in_len == (HEADER_LEN + *length))
            {
                // 数据是完整的，没有剩余待解析的数据
                *next = NULL;
                *next_len = 0;
                return 1;
            }
            *next = (in + HEADER_LEN + *length);
            *next_len = (in_len - HEADER_LEN - *length);
            return 1;
        }
        // 不是vpn协议
        // *next = NULL;
        *next_len = 0;
        return -1;
    }
#ifdef __cplusplus
}
#endif