#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wasi/api.h>

int32_t imported_wasi_snapshot_preview1_magic_new_function(int32_t) __attribute__((
    __import_module__("wasi_snapshot_preview1"),
    __import_name__("magic_new_function")
));

__wasi_errno_t wasi_magic_new_function(__wasi_fd_t *retptr0)
{
    int32_t ret = imported_wasi_snapshot_preview1_magic_new_function((int32_t)retptr0);
    return (uint16_t) ret;
}

int magic_new_function(void)
{
    __wasi_fd_t newfd;
    __wasi_errno_t error = wasi_magic_new_function(&newfd);
    if (error) {
        errno = error;
        return -1;
    }
    return newfd;
}

// The standard implementation of assert raises a signal on failure,
// which causes the Wasm engine to terminate in a confusing way with
// no indication of which assertion failed, so we use this instead:

#define assert(x) do { if (!(x)) { \
        assert_fail(__FILE__, __LINE__, __func__, #x); } } while (0)

void assert_fail(const char *file, unsigned long long line,
                 const char *func, const char *cond)
{
    fprintf(stderr, "%s:%llu: %s: Assertion '%s' failed.\n",
            file, line, func, cond);
    exit(1);
}

int main()
{
    int fd = magic_new_function();
    assert(fd >= 0);

    uint8_t data[10000];
    for (size_t i = 0; i < sizeof(data); i++)
        data[i] = i % 251;
    size_t len = sizeof(data);
    size_t off = len / 3;
    assert(write(fd, data, len) == len);
    assert(lseek(fd, off, SEEK_SET) == off);
    uint8_t buf[sizeof(data)];
    assert(read(fd, buf, len) == len - off);
    assert(!memcmp(data + off, buf, len - off));
    printf("PASS\n");

    return 0;
}
