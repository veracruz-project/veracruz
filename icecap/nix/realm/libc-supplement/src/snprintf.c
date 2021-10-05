/*
 * AUTHORS
 *
 * The Veracruz Development Team.
 *
 * COPYRIGHT
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory for licensing
 * and copyright information.
 *
 */

#include <stdio.h>

int snprintf(char *str, size_t size, const char *format, ...) {
    // HACK
    printf("snprintf(_, _, \"%s\")\n", format);
    strcpy(str, format);
    return 0;
}
