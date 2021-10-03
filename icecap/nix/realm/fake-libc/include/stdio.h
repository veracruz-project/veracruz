#pragma once

#include <stddef.h>
#include <icecap_utils.h>

#define printf icecap_utils_debug_printf

int snprintf(char *str, size_t size, const char *format, ...);
