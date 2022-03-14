/*
 * HTTP convenience functions, these just wrap the low-level HTTP API
 * that Zephyr provides
 *
 * ## Authors
 * 
 * The Veracruz Development Team.
 *
 * ## Licensing and copyright notice
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
 * information on licensing and copyright.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef HTTP_H
#define HTTP_H

// Timeout for HTTP transactions in milliseconds
#ifndef HTTP_TIMEOUT
#define HTTP_TIMEOUT 10000
#endif

// Number of retries before returning an error
#ifndef HTTP_RETRIES
#define HTTP_RETRIES 3
#endif

// HTTP GET operation
//
// - host     Hostname or url of server to access
// - port     Port of server to access
// - path     Path on the server to access
// - buf      Buffer to write response into
// - buf_len  Size of response buffer in bytes
//
// Returns the number of bytes recieved, or a negative error code
ssize_t http_get(
        const char *host,
        uint16_t port,
        const char *path,
        uint8_t *buf,
        size_t buf_len);

// HTTP POST operation
//
// - host             Hostname or url of server to access
// - port             Port of server to access
// - path             Path on the server to access
// - payload_buf      Buffer of data to send with POST message
// - payload_buf_len  Size of payload buffer in bytes
// - resp_buf         Buffer to write response into
// - resp_buf_len     Size of response buffer in bytes
//
// Returns the number of bytes recieved, or a negative error code
ssize_t http_post(
        const char *host,
        uint16_t port,
        const char *path,
        const uint8_t *payload_buf,
        size_t payload_buf_len,
        uint8_t *resp_buf,
        size_t resp_buf_len);

#endif
