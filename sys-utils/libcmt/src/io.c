/* Copyright Cartesi and individual authors (see AUTHORS)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "io.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/cartesi/cmio.h>

int cmt_io_init(cmt_io_driver_t *_me) {
    int rc = 0;

    if (!_me)
        return -EINVAL;
    cmt_io_driver_ioctl_t *me = &_me->ioctl;
    me->fd = open("/dev/cmio", O_RDWR);

    if (me->fd < 0) {
        rc = -errno;
        return rc;
    }

    struct cmio_setup setup;
    if (ioctl(me->fd, IOCTL_CMIO_SETUP, &setup)) {
        rc = -errno;
        goto do_close;
    }

    void *tx = mmap((void *) setup.tx.data, setup.tx.length, PROT_READ | PROT_WRITE, MAP_SHARED, me->fd, 0);
    if (tx == MAP_FAILED) {
        rc = -errno;
        goto do_close;
    }

    void *rx = mmap((void *) setup.rx.data, setup.rx.length, PROT_READ, MAP_SHARED, me->fd, 0);
    if (rx == MAP_FAILED) {
        rc = -errno;
        goto do_unmap;
    }

    me->rx_max_length = setup.rx.length;
    me->rx_fromhost_length = 0;

    cmt_buf_init(me->tx, setup.tx.length, tx);
    cmt_buf_init(me->rx, setup.rx.length, rx);
    return 0;

do_unmap:
    munmap(tx, setup.tx.length);
do_close:
    close(me->fd);
    return rc;
}

void cmt_io_fini(cmt_io_driver_t *_me) {
    if (!_me)
        return;
    cmt_io_driver_ioctl_t *me = &_me->ioctl;

    munmap(me->tx->begin, cmt_buf_length(me->tx));
    munmap(me->rx->begin, cmt_buf_length(me->rx));
    close(me->fd);

    memset(me, 0, sizeof(*me));
    me->fd = -1;
}

cmt_buf_t cmt_io_get_tx(cmt_io_driver_t *me) {
    static const cmt_buf_t empty = {NULL, NULL};
    if (!me)
        return empty;
    return *me->ioctl.tx;
}

static uint32_t min(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

cmt_buf_t cmt_io_get_rx(cmt_io_driver_t *me) {
    static const cmt_buf_t empty = {NULL, NULL};
    if (!me)
        return empty;
    cmt_buf_t rx = *me->ioctl.rx;
    rx.end = rx.begin + min(me->ioctl.rx_max_length, me->ioctl.rx_fromhost_length);
    return rx;
}

static uint64_t pack(struct cmt_io_yield *rr) {
    return ((uint64_t) rr->dev << 56) | ((uint64_t) rr->cmd << 56 >> 8) | ((uint64_t) rr->reason << 48 >> 16) |
        ((uint64_t) rr->data << 32 >> 32);
}

static struct cmt_io_yield unpack(uint64_t x) {
    struct cmt_io_yield out = {
        (uint64_t) x >> 56,
        (uint64_t) x << 8 >> 56,
        (uint64_t) x << 16 >> 48,
        (uint64_t) x << 32 >> 32,
    };
    return out;
}

int cmt_io_yield(cmt_io_driver_t *_me, struct cmt_io_yield *rr) {
    if (!_me)
        return -EINVAL;
    if (!rr)
        return -EINVAL;
    cmt_io_driver_ioctl_t *me = &_me->ioctl;

    static bool checked = false, enabled = false;

    if (!checked) {
        enabled = getenv("CMT_DEBUG") != NULL;
        checked = true;
    }

    if (enabled) {
        fprintf(stderr,
            "tohost {\n"
            "\t.dev = %d,\n"
            "\t.cmd = %d,\n"
            "\t.reason = %d,\n"
            "\t.data = %d,\n"
            "};\n",
            rr->dev, rr->cmd, rr->reason, rr->data);
    }
    uint64_t req = pack(rr);
    if (ioctl(me->fd, IOCTL_CMIO_YIELD, &req))
        return -errno;
    *rr = unpack(req);

    me->rx_fromhost_length = rr->data;

    if (enabled) {
        fprintf(stderr,
            "fromhost {\n"
            "\t.dev = %d,\n"
            "\t.cmd = %d,\n"
            "\t.reason = %d,\n"
            "\t.data = %d,\n"
            "};\n",
            rr->dev, rr->cmd, rr->reason, rr->data);
    }
    return 0;
}
