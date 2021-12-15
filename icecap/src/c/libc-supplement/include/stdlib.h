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

#pragma once

#include <stddef.h>

void *calloc(size_t nelem, size_t elsize);

static inline void *malloc(size_t nelem) {
    return calloc(nelem, 1);
}

void free(void *ptr);
