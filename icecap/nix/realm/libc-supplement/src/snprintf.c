#include <stdio.h>

int snprintf(char *str, size_t size, const char *format, ...) {
    // HACK
    printf("snprintf(_, _, \"%s\")\n", format);
    strcpy(str, format);
    return 0;
}