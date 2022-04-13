// AUTHORS
//
// The Veracruz Development Team.
//
// COPYRIGHT
//
// See the `LICENSE_MIT.markdown` file in the Veracruz root directory
// for licensing and copyright information.

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wasi/api.h>

////////////////////////////////////////////////////////////////////////////
// This part should probably be in a Veracruz library.

int32_t imported_veracruz_fd_create(int32_t) __attribute__((
    __import_module__("veracruz_si"),
    __import_name__("fd_create")
));

__wasi_errno_t veracruz_fd_create(__wasi_fd_t *retptr0)
{
    int32_t ret = imported_veracruz_fd_create((int32_t)retptr0);
    return (uint16_t)ret;
}

int fd_create(void)
{
    __wasi_fd_t newfd;
    __wasi_errno_t error = veracruz_fd_create(&newfd);
    if (error) {
        errno = error;
        return -1;
    }
    return newfd;
}

////////////////////////////////////////////////////////////////////////////
// The standard implementation of assert raises a signal on failure,
// which causes the Wasm engine to terminate in a confusing way with
// no indication of which assertion failed, so we use this instead.

#define assert(x) do { if (!(x)) { \
        assert_fail(__FILE__, __LINE__, __func__, #x); } } while (0)

void assert_fail(const char *file, unsigned long long line,
                 const char *func, const char *cond)
{
    fprintf(stderr, "%s:%llu: %s: Assertion '%s' failed.\n",
            file, line, func, cond);
    exit(1);
}

////////////////////////////////////////////////////////////////////////////
// A simple test.F

int main()
{
    // Create the temporary file.
    int fd = fd_create();
    assert(fd >= 0);

    // Write some data to the file.
    uint8_t data[10000];
    const size_t len = sizeof(data);
    for (size_t i = 0; i < len; i++)
        data[i] = i % 251;
    assert(write(fd, data, len) == len);

    // Seek to an offset.
    size_t off = len / 3;
    assert(lseek(fd, off, SEEK_SET) == off);

    // Read data from file and compare.
    uint8_t buf[sizeof(data)] = { 0 };
    assert(read(fd, buf, len) == len - off);
    assert(!memcmp(data + off, buf, len - off));

    printf("PASS\n");

    return 0;
}
