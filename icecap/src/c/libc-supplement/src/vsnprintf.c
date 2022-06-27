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
#include <string.h>

int vsnprintf(char *str, size_t size, const char *format, __builtin_va_list ap)
{
    // HACK instead of implementing vsnprintf, just:
    //  - copy the format string directly
    size_t i;
    for (i = 0; i < size - 1 && format[i] != '\0'; i++)
        str[i] = format[i];
    str[i] = '\0';
    return strlen(format);
}
