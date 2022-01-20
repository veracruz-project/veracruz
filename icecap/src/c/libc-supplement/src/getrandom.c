/*
 * AUTHORS
 *
 * The Veracruz Development Team.
 *
 * COPYRIGHT
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory
 * for licensing and copyright information.
 *
 */

#include <string.h>
#include <sys/random.h>

// FIXME: Bogus and potentially dangerous implementation of getrandom.
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
    memset(buf, 0, buflen);
    return buflen;
}
