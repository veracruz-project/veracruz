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

typedef struct { void *x; } FILE;

int printf(const char *format, ...);
int puts(const char *s);
int snprintf(char *str, size_t size, const char *format, ...);
int vsnprintf(char *str, size_t size, const char *format, __builtin_va_list ap);
