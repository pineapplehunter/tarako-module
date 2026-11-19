/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "evidence.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_blob(int dir, const char *path, uint8_t *buffer, size_t *length)
{
    int fd = openat(dir, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    size_t used = 0;
    for (;;) {
        uint8_t extra;
        ssize_t n = used == *length ? read(fd, &extra, 1) :
            read(fd, buffer + used, *length - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || used == *length) {
            if (n > 0)
                errno = EOVERFLOW;
            int saved = errno;
            close(fd);
            errno = saved;
            *length = used;
            return n == 0;
        }
        used += (size_t)n;
    }
}

static int ima_active(void)
{
    uint8_t state[3];
    size_t size = sizeof(state);
    if (read_blob(AT_FDCWD, "/sys/kernel/ima_rtmr/disabled", state, &size) &&
        size == 2 && memcmp(state, "0\n", 2) == 0)
        return 1;
    fputs("IMA RTMR extender is unavailable or disabled\n", stderr);
    return 0;
}

int tdx_quote(uint8_t *output, size_t *size, const uint8_t report[64])
{
    if (!ima_active())
        return 0;
    char instance[] = "/sys/kernel/config/tsm/report/tarako-XXXXXX";
    if (!mkdtemp(instance)) {
        perror("TDX TSM report instance");
        return 0;
    }
    int dir = open(instance, O_DIRECTORY | O_CLOEXEC | O_RDONLY);
    int ok = 0;
    if (dir < 0) {
        perror("TDX TSM open instance");
        goto done;
    }
    uint8_t provider[32];
    size_t provider_size = sizeof(provider);
    if (!read_blob(dir, "provider", provider, &provider_size) ||
        ((provider_size != 9 || memcmp(provider, "tdx_guest", 9)) &&
         (provider_size != 10 || memcmp(provider, "tdx_guest\n", 10)))) {
        fputs("TDX TSM provider is not tdx_guest\n", stderr);
        goto done;
    }
    int in = openat(dir, "inblob", O_WRONLY | O_CLOEXEC);
    if (in < 0) {
        perror("TDX TSM open inblob");
        goto done;
    }
    ssize_t n;
    do {
        n = write(in, report, 64);
    } while (n < 0 && errno == EINTR);
    int saved = errno;
    int rc = close(in);
    if (n != 64 || rc != 0) {
        if (n < 0)
            errno = saved;
        else if (rc == 0)
            errno = EIO;
        perror("TDX TSM write inblob");
        goto done;
    }
    if (!read_blob(dir, "outblob", output, size)) {
        perror("TDX TSM GetQuote");
        goto done;
    }
    if (*size == 0) {
        fputs("TDX TSM returned an empty quote\n", stderr);
        goto done;
    }
    ok = ima_active();
done:
    if (dir >= 0)
        close(dir);
    if (rmdir(instance) != 0) {
        perror("TDX TSM remove instance");
        ok = 0;
    }
    return ok;
}
