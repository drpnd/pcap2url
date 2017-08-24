/*_
 * Copyright (c) 2010,2017 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _ANACAP_PRIVATE_H
#define _ANACAP_PRIVATE_H

#include <stdint.h>

#define _MAX_PACKET_SIZE 0x1000

enum _endian {
    _ENDIAN_MACHINE,
    _ENDIAN_NETWORK,
};

#ifdef __cplusplus
extern "C" {
#endif

    uint16_t bs2uint16(const unsigned char *, enum _endian);
    uint32_t bs2uint32(const unsigned char *, enum _endian);

    int
    proc_l2_ethernet(anacap_t *, anacap_packet_t *, unsigned char *, size_t);

    int proc_l3_ipv4(anacap_t *, anacap_packet_t *, uint8_t *, size_t);
    int proc_l3_ipv6(anacap_t *, anacap_packet_t *, uint8_t *, size_t);

    int proc_l4_tcp(anacap_t *, anacap_packet_t *, uint8_t *, size_t );
    int proc_l4_udp(anacap_t *, anacap_packet_t *, uint8_t *, size_t );

#ifdef __cplusplus
}
#endif

#endif /* _ANACAP_PRIVATE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
