#include <wasi/api.h>

void magic_new_function(void) __attribute__((
    __import_module__("wasi_snapshot_preview1"),
    __import_name__("magic_new_function")
));

int main()
{
    magic_new_function();
    return 0;
}
