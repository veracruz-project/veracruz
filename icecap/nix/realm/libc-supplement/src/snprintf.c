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
    // HACK instead of implementing sprintf, just:
    //  - log when it's used (so far it isn't), and
    //  - copy the format string directly
    printf("snprintf(_, _, \"%s\")\n", format);
    strcpy(str, format);
    return 0;
}
