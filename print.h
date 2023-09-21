#include <stdint.h>

#ifndef SSLVPN_TEST_PRINT_H
#define SSLVPN_TEST_PRINT_H

#ifdef __cplusplus
extern "C"
{
#endif

    void dump_hex(const uint8_t *buf, uint32_t size, uint32_t number);

#ifdef __cplusplus
}
#endif

#endif